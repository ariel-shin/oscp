* Detection: Finding Missing Software Patches
	* Powershell
		* Get-HotFix
		```get-hotfix
		Get-HotFix | Sort-Object HotFixID
		```
		* Windows Management Instrumentation (MWI)
		```wmi
		Get-WmiObject -Class "win32_quickfixengineering" | Select-Object -Property "Description", "HotfixID", @{Name="InstalledOn"; Expression={([DateTime]($_.InstalledOn)).ToLocalTime}}
		```
		* Sherlock (rasta-mouse)
		```
		\\File cannot be loaded...not digitally signed
		Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

		Import-Module .\Sherlock.ps1

		Find-AllVulns
		```
	* Command Prompt
		* Windows Management Instrumentation Console (WMIC)
		```
		wmic.exe qfe list full 
		```
		* windows-privesc-check (pentestmonkey)
		```
		windows-privesc-check2.exe --audit -T auto -o report
		```
		* Windows-Exploit-Suggester (GDSSecurity)
	* Metasploit
		* post/windows/gather/enum_patches
		* post/multi/recon/local_exploit_suggester
* Detection: Finding DLL Hijacking
	* PAGE 15 - 17
* Detection: Finding binPath 
	* sc.exe sdshow <service_name>
	* accesschk.exe -uvwc <service_name>
	