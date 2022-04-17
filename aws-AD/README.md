# AWSCLI



## Show keypairs

```
aws ec2 describe-key-pairs
```

```
privkey='/mnt/Dropbox/Calibre-Kindle-Unlimited/simplilearn-CEHv10/CPENT/PracticeRange/AWS/AWS-Kali-aka.pem'
ID='ami-08aa543413d7bdc57'
```





## Run Server 2019



```
cat user_data.txt 
<powershell>
$Secure_String_Pwd = ConvertTo-SecureString "P@ssW0rD!" -AsPlainText -Force
New-LocalUser -AccountNeverExpires -Description "Amit Agarwal" -FullName "Amit Agarwal" -Name amitag -PasswordNeverExpires  -Password $Secure_String_Pwd
</powershell>

```





```
aws ec2 run-instances --image-id ami-08ed5c5dd62794ec0 --count 1 --instance-type t2.micro --key-name aka --security-group-ids sg-047fcbab42580b283 --subnet-id  subnet-854a1eda --user-data file://ignored/user_data-ad.txt
```





## Server 2016



```
ID=ami-08aa543413d7bdc57
aws ec2 run-instances --image-id $ID --count 1 --instance-type t2.micro --key-name aka --security-group-ids sg-047fcbab42580b283 --subnet-id  subnet-854a1eda --user-data file://ignored/user_data-ad.txt
```





## List instances



```
aws ec2 describe-instances --filters "Name=instance-type,Values=t2.micro" --query "Reservations[].Instances[].InstanceId"
id=$(aws ec2 describe-instances --filters Name=instance-type,Values=t2.micro Name=instance-state-name,Values=running --query "Reservations[].Instances[].InstanceId" --output text)


#Describe
aws ec2 describe-instances --filters "Name=tag:Name,Values=MyInstance"
```





## Terminate



```
aws ec2 terminate-instances --instance-ids $id
```



## Get password



```
aws ec2 get-password-data --instance-id i-0b70221b5e31872b0

## Decrypted password

aws ec2 get-password-data --instance-id  i-0b70221b5e31872b0 --priv-launch-key /mnt/Dropbox/Calibre-Kindle-Unlimited/simplilearn-CEHv10/CPENT/PracticeRange/AWS/AWS-Kali-aka.pem
```


## Get public IP address



```
aws ec2 describe-instances --instance-ids $id --query 'Reservations[*].Instances[*].PublicIpAddress' --output text

ip=$(aws ec2 describe-instances --instance-ids $id --query 'Reservations[*].Instances[*].PublicIpAddress' --output text)

```



## Login to server



```
xfreerdp /p:'C%pmoQbTrza)x4qn622e*G$9SRTh-FkI'  /u:Administrator /v:3.92.59.55 /dynamic-resolution +clipbaord

xfreerdp /p:"$pw"  /u:Administrator /v:"$ip" /dynamic-resolution +clipboard /cert:ignore +auto-reconnect
```



## Logs



You can't find the user data logs

The log files for EC2Launch v2, EC2Launch, and EC2Config  contain the output from the standard output and standard error streams.  You can access the log files at the following locations:

**EC2Launch** v2: C:\ProgramData\Amazon\EC2Launch\log\agent.log

**EC2Launch:** C:\ProgramData\Amazon\EC2-Windows\Launch\Log\UserdataExecution.log

**EC2Config:** C:\Program Files\Amazon\Ec2ConfigService\Logs\Ec2Config.log

**Windows 2016** C:\ProgramData\Amazon\EC2-Windows\Launch\Log\UserdataExecution.log

# Install AD with powershell



## Get The AD Service Name



```
get-windowsfeature
```



## Install AD service



```
install-windowsfeature AD-Domain-Services
```



## Import Module



```
Import-Module ADDSDeployment
```



## Promote to DC



```
$Secure_String_Pwd = ConvertTo-SecureString "P@ssW0rD!" -AsPlainText -Force

Install-ADDSForest -CreateDnsDelegation:$false -DatabasePath “C:\Windows\NTDS” -DomainMode “Win2012R2” -DomainName “phantom.com” -DomainNetbiosName “PHANTOM” -ForestMode “Win2012R2” -InstallDns:$true -LogPath “C:\Windows\NTDS” -NoRebootOnCompletion:$false -SysvolPath “C:\Windows\SYSVOL” -Force:$true -SafeModeAdministratorPassword $Secure_String_Pwd -NoRebootOnCompletion
```





**Forest and Domain modes can be Win2012R2 or Win2008**



| **Command**                                    | **Description**                                              |
| ---------------------------------------------- | ------------------------------------------------------------ |
| Add-ADDSReadOnlyDomainControllerAccount        | Install read only domain controller                          |
| Install-ADDSDomain                             | Install first domain controller in a child or tree domain    |
| Install-ADDSDomainController                   | Install additional domain controller in domain               |
| Install-ADDSForest                             | Install first domain controller in new forest                |
| Test-ADDSDomainControllerInstallation          | Verify prerequisites to install additional domain controller in domain |
| Test-ADDSDomainControllerUninstallation        | Uninstall AD services from server                            |
| Test-ADDSDomainInstallation                    | Verify prerequisites to install first domain controller in a child or tree domain |
| Test-ADDSForestInstallation                    | Install first domain controller in new forest                |
| Test-ADDSReadOnlyDomainControllAccountCreation | Verify prerequisites to install read only domain controller  |
| Uninstall-ADDSDomainController                 | Uninstall the domain controller from server                  |





## Download and unzip badblood



```
Add-Type -assembly "System.IO.Compression.Filesystem";
[String]$Source = "https://github.com/davidprowe/BadBlood/archive/refs/heads/master.zip" ;
[String]$Destination = "C:\badblood" ;
mkdir $Destination
[String]$ss="c:\badblood\badblood.zip"
(New-Object System.Net.WebClient).DownloadFile($Source, $ss)
[IO.Compression.Zipfile]::ExtractToDirectory($ss, $Destination);
```





## Run badblood with less users



```
.\invoke-badblood.ps1 10 5 10 -NonInteractive
```

