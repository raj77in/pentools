<powershell>
# Steal (shamelessly) from commando vm on using BoxStarter to handle reboots
#
# Temp Folder
if (!(Get-Item C:\temp -ea ignore)) { mkdir C:\temp }

#log everthing
$logfilepath="c:\temp\Log.log"
Start-Transcript -Path c:\temp\Log.log
function installBoxStarter()
{
  <#
    .SYNOPSIS
    Install BoxStarter on the current system  
    .DESCRIPTION
    Install BoxStarter on the current system. Returns $true or $false to indicate success or failure. On
    fresh windows 7 systems, some root certificates are not installed and updated properly. Therefore,
          this funciton also temporarily trust all certificates before installing BoxStarter.  
#> 


# Try to install BoxStarter as is first, then fall back to be over trusing only if this step fails.
            try {
		          iex ((New-Object System.Net.WebClient).DownloadString('https://boxstarter.org/bootstrapper.ps1')); get-boxstarter -Force
		            return $true
	          } catch {
	          }

# https://stackoverflow.com/questions/11696944/powershell-v3-invoke-webrequest-https-error
# Allows current PowerShell session to trust all certificates
# Also a good find: https://www.briantist.com/errors/could-not-establish-trust-relationship-for-the-ssltls-secure-channel/

  try {
    Add-Type @"
      using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
  	  public bool CheckValidationResult(
  		    ServicePoint srvPoint, X509Certificate certificate,
  		    WebRequest request, int certificateProblem) {
  		  return true;
  	  }
    }
"@
  } catch {
    Write-Debug "Failed to add new type"
  }  
  try {
  	$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
  } catch {
  	Write-Debug "Failed to find SSL type...1"
  }  
  try {
  	$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls'
  } catch {
  	Write-Debug "Failed to find SSL type...2"
  }  
  $prevSecProtocol = [System.Net.ServicePointManager]::SecurityProtocol
    $prevCertPolicy = [System.Net.ServicePointManager]::CertificatePolicy  
    Write-Host "[+] Installing Boxstarter"
# Become overly trusting
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy  
# download and instal boxstarter
      iex ((New-Object System.Net.WebClient).DownloadString('https://boxstarter.org/bootstrapper.ps1')); get-boxstarter -Force  
# Restore previous trust settings for this PowerShell session
# Note: SSL certs trusted from installing BoxStarter above will be trusted for the remaining PS session
        [System.Net.ServicePointManager]::SecurityProtocol = $prevSecProtocol
        [System.Net.ServicePointManager]::CertificatePolicy = $prevCertPolicy
          return $true
}


## BoxStarter

# Get user credentials for autologin during reboots
# Write-Host "[+] Getting user credentials ..."
# Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds" -Name "ConsolePrompting" -Value $True

# We are going to create this user


Write-Host "[+] Installing Boxstarter"
$rc = installBoxStarter
if ( -Not $rc ) {
	Write-Host "[ERR] Failed to install BoxStarter"
	  Read-Host  "      Press ANY key to continue..."
	  exit 1
}


$filecontent = @'


# Create new user
$password = ConvertTo-SecureString "password" -AsPlainText -Force
$cred=New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList "amitag", $password


New-LocalUser -AccountNeverExpires -Description "Amit Agarwal" -FullName "Amit Agarwal" -Name amitag -PasswordNeverExpires  -Password $password
Add-LocalGroupMember -Group "Administrators" -Member "amitag"

# Install AD
install-windowsfeature AD-Domain-Services
Import-Module ADDSDeployment

$Secure_String_Pwd = ConvertTo-SecureString "password" -AsPlainText -Force
Install-ADDSForest -CreateDnsDelegation:$false -DatabasePath “C:\Windows\NTDS” -DomainMode “Win2008” -DomainName “phantom.com” -DomainNetbiosName “PHANTOM” -ForestMode “Win2008” -InstallDns:$true -LogPath “C:\Windows\NTDS” -SysvolPath “C:\Windows\SYSVOL” -Force:$true -SafeModeAdministratorPassword $Secure_String_Pwd

# Restart-Computer -Force

# Fill in anything needed on third reboot; remove if unneeded
# Create more reboots as needed
# Download and extract badblood

Add-Type -assembly "System.IO.Compression.Filesystem";
[String]$Source = "https://github.com/davidprowe/BadBlood/archive/refs/heads/master.zip" ;
[String]$Destination = "C:\badblood" ;
mkdir $Destination
[String]$ss="c:\badblood\badblood.zip"
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
(New-Object System.Net.WebClient).DownloadFile($Source, $ss)
  [IO.Compression.Zipfile]::ExtractToDirectory($ss, $Destination);
## Create users 
# Parameters 1=> users, 2nd is Groups and 3rd is Computers
  cd \badblood\Badblood-master
  .\invoke-badblood.ps1 100 25 100 -NonInteractive

## Rename the instance
Rename-Computer -NewName DC001

## Group policy  - disable Defender
# Restart-Computer

'@

$filecontent | Out-File c:\temp\install.ps1 -Encoding 'OEM'

# Boxstarter options
$Boxstarter.RebootOk = $true    # Allow reboots?
$Boxstarter.NoPassword = $false # Is this a machine with no login password?
$Boxstarter.AutoLogin = $true   # Save my password securely and auto-login after a reboot

Install-BoxstarterPackage -PackageName c:\temp\install.ps1

Stop-Transcript


</powershell>

