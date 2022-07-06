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
$DCAddress = 1.1.1.1

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
  $Secure_String_Pwd = ConvertTo-SecureString 'P123$assword' -AsPlainText -Force
    New-LocalUser -AccountNeverExpires -Description "Amit Agarwal" -FullName "Amit Agarwal" -Name amitag -PasswordNeverExpires  -Password $Secure_String_Pwd
    Add-LocalGroupMember -Group "Administrators" -Member "amitag"

        
        ##################################################
        ###############     --REBOOT--     ###############
    }
    
    2 {
        # Fill in anything needed on second reboot; remove if unneeded
# Join AD
            Set-DnsClientServerAddress -InterfaceIndex 1 -ServerAddresses ($DCAddress, "1.1.1.1")
            add-computer –domainname "PHANTOM"  -restart
                
        Restart-Computer
        ##################################################
        ###############     --REBOOT--     ###############
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

