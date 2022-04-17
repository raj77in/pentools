<powershell>
# From https://community.spiceworks.com/topic/1450724-powershell-script-continue-after-reboot

# Temp Folder
if (!(Get-Item C:\temp -ea ignore)) { mkdir C:\temp }

$dropperscript = 'C:\temp\dropper.ps1'

$dropper = @'
#############################################
###        Configuration Variables        ###
                                            #
# Put any variables you'll use here
                                            # 
###                                       ###
#############################################

# Static Variables
$countfile = 'C:\temp\bootcount.txt'
$bootbatch = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\dropper.bat'
$dropperscript = 'C:\temp\dropper.ps1'

#################
##### Setup #####

# Bootstrap Batch
if (!(Get-Item $bootbatch -ea ignore)) {
    "powershell -c $dropperscript`npause" | Out-File $bootbatch -Encoding 'OEM'
}

# Boot Count
if (Get-Item $countfile -ea ignore) {
    [int]$bootcount = Get-Content $countfile
    if ($bootcount -match "^\d{1,2}$") { ([int]$bootcount) ++ }
    else { $bootcount = 1 }
}
else { $bootcount = 1 }
$bootcount | Out-File $countfile


switch ($bootcount) {
    
    1 {
        # Fill in anything needed on first run
# Create new user
  $Secure_String_Pwd = ConvertTo-SecureString "password" -AsPlainText -Force
    New-LocalUser -AccountNeverExpires -Description "Amit Agarwal" -FullName "Amit Agarwal" -Name amitag -PasswordNeverExpires  -Password $Secure_String_Pwd
    Add-LocalGroupMember -Group "Administrators" -Member "amitag"

        
        Restart-Computer
        ##################################################
        ###############     --REBOOT--     ###############
    }
    
    2 {
        # Fill in anything needed on second reboot; remove if unneeded
# Install AD
    install-windowsfeature AD-Domain-Services
    Import-Module ADDSDeployment

    $Secure_String_Pwd = ConvertTo-SecureString "password" -AsPlainText -Force
    Install-ADDSForest -CreateDnsDelegation:$false -DatabasePath “C:\Windows\NTDS” -DomainMode “Win2008” -DomainName “phantom.com” -DomainNetbiosName “PHANTOM” -ForestMode “Win2008” -InstallDns:$true -LogPath “C:\Windows\NTDS” -NoRebootOnCompletion:$false -SysvolPath “C:\Windows\SYSVOL” -Force:$true -SafeModeAdministratorPassword $Secure_String_Pwd


            
        Restart-Computer
        ##################################################
        ###############     --REBOOT--     ###############
    }
    
    3 {
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
    .\invoke-badblood.ps1 10 5 10 -NonInteractive

## Rename the instance
    Rename-Computer -NewName DC001

## Group policy  - disable Defender


        
        Restart-Computer
        ##################################################
        ###############      --END--      ################
    }
    
    default {
        # Dropper is complete; clean up
        rm $countfile
        rm $bootbatch
        rm $dropperscript
    }
}
'@



  # Drop and run Dropper

$dropper | Out-File $dropperscript -Encoding 'OEM'

Invoke-Expression $dropperscript

  </powershell>

