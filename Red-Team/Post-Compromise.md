
This room is part of tryhackme's lay of land room from red teaming path and focuses on enumeration done after post compromise . 


# Network enumeration 


This command is used to display active network connections and their respective network addresses in numerical form.

```
netstat -n
```


You can also use (not recommended as it will display all active ports on the system and might trigger some security thing) 

```c
netstat -na
```

Looking for arp table . It can be used to know about different devices present on the network and might be usefully in pivoting / routing 

```c
arp -a 
```

# Active directory enum

You can use this command to find the name of domain the user is part of in active diretory environment . 

```c
systeminfo | findstr Domain
```

The following are Active Directory Administrators accounts:

| Account Name        | Description                                                       |
|---------------------|-------------------------------------------------------------------|
| BUILTIN\Administrator | Local admin access on a domain controller                          |
| Domain Admins        | Administrative access to all resources in the domain              |
| Enterprise Admins    | Available only in the forest root                                  |
| Schema Admins        | Capable of modifying domain/forest; useful for red teamers         |
| Server Operators     | Can manage domain servers                                          |
| Account Operators    | Can manage users that are not in privileged groups                 |


One can use this command to get a list of all active user's on active directrory environment 

```powershell
Get-ADUser -Filter * 
```

One can also use ```SearchBase``` option, we specify a specific Common-Name CN in the active directory. 

```powershell
Get-ADUser -Filter * -SearchBase "CN=Users,DC=THMREDTEAM,DC=COM"
```

# Host security (Antivirus)


Looking for present anti-virus on the machine 

```c
wmic /namespace:\\root\securitycenter2 path antivirusproduct
```
Note:- It might not work on some machines as securitycenter2 might not be present , But it should work on almost every Windows workstaion 


Looking for windows defender status 

```powershell
Get-Service Windefend
```

One can use this command to get more information like ant-spyware etc...

```
Get-MPComputerstatus
```

One can use this command to look for Host based firewall status

```powershell
Get-NetFirewallProfile
```

Or use this command to just find about if it is enabled or not 

```powershell
Get-NetFirewallProfile | Format-Table Name, Enabled
```


# Enumerating Security Solutions 


One can use this command to find out available event logs on the machine 

```powershell
Get-EventLog -list
```

One can use this command to find if sysmon is running on the machine or not (Sysmon is a logging tool which is used by blue team folks to monitor different events)

```powershell
Get-Process | Where-Object { $_.ProcessName -eq "Sysmon" }
```

Or by checking the registry 

```c
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational
```

You can also use this command to look for Sysmon's config file 

```powershell
findstr /si '<ProcessCreate onmatch="exclude">' C:\tools\*
```

**For EDR**

You can use the following tools https://github.com/PwnDexter/SharpEDRChecker & https://github.com/PwnDexter/Invoke-EDRChecker


# Application & Services 


Looking for installed program 

```c
wmic product get name,version
```

Looking for hiddent files

```powershell
Get-ChildItem -Hidden -Path C:\Users\kkidd\Desktop\
```

You can list all the running services by using this command 

```powershell
net start
```

We can also look for specific service process information 

```powershell
Get-Process -Name Nameoftheprocess
```

Then you can use netstat to look for open ports for that specific service 

```powershell
netstat -noa |findstr "LISTENING" |findstr "ServiceID"
```

