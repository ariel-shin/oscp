# ariel-shin Linux - Privilege Escalation 

## MUST RUN: ipconfig/ifconfig && whoami && cat local.txt/proof.txt

## Summary 
* [Process](#Process)
* [Cracking Passwords](#Cracking-Passwords)
* [Automated Scripts](#Automated-Scripts)
* [What to do when youre stuck](#What-to-do-when-youre-stuck)

## Process
* Upgrade the shell
```
python -c ‘import pty; pty.spawn(“/bin/sh”)’
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
fine . -iname '*config'
```

* mysql
```mysql
mysql -uroot -ppassword -e 'show databases;' //no spaces for password
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
* [LinEnum](https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh)
* [Unix-Privesc-Check](https://github.com/pentestmonkey/unix-privesc-check)

[Back](#summary)

## What to do when you're stuck
* [Calm down](https://www.youtube.com/watch?v=F28MGLlpP90)
* Take a breath 
* Look for usernames that could have been found
	* Try to ssh by guessing credentials
* Google anything running by root

[Back](#summary)