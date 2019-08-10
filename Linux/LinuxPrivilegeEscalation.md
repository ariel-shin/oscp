# ariel-shin Linux - Privilege Escalation 

## Summary 

## Process
* What's the OS? Version? Architecture? 
```os
cat etc/*-release
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
```

* Who uses the box? What users?
```passwd
cat /etc/passwd
grep -vE "nologin | false" /etc/passwd
```

* Can we access /etc/shadow
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

## Automated Scripts
* [LinEnum](https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh)
* [Unix-Privesc-Check](https://github.com/pentestmonkey/unix-privesc-check)
