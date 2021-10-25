. "$PSScriptRoot\Enums.ps1"
. "$PSScriptRoot\Logger.ps1" -LogFile "$env:COMPUTERNAME.log" -LogFolder "Logs" -WriteToHost:$false

Function Get-InstalledSoftware {
    Write-Log "Searching for software on $env:COMPUTERNAME"

    $regSoftware = @()
    $software = @()

    $uninstallRegLocation1 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    $uninstallRegLocation2 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall";

    Write-Log "Searching registry '$uninstallRegLocation1' for software."
    $regSoftware += Get-ChildItem "$uninstallRegLocation1\*" | % { Get-ItemProperty $_.Name.Replace("HKEY_LOCAL_MACHINE", "HKLM:") -ErrorAction SilentlyContinue }
    $count = $regSoftware.Count
    Write-Log "Found $count pieces of software."

    Write-Log "Searching registry '$uninstallRegLocation2' for software."
    $regSoftware += Get-ChildItem "$uninstallRegLocation2\*" | % { Get-ItemProperty $_.Name.Replace("HKEY_LOCAL_MACHINE", "HKLM:") -ErrorAction SilentlyContinue }
    $count = $regSoftware.Count - $count
    Write-Log "Found $count pieces of software."

    $regSoftware = $regSoftware | ? { $_.DisplayName } |  Sort-Object -Unique -Property DisplayName


    foreach ($installedSoftware in $regSoftware) {
        $software += [PSCustomObject]@{
            Name             = $installedSoftware.DisplayName;
            Version          = $installedSoftware.Version;
            VersionMinor     = $installedSoftware.VersionMinor;
            VersionMajor     = $installedSoftware.VersionMajor;
            SystemComponent  = $installedSoftware.SystemComponent;
            Readme           = $installedSoftware.Readme; # Not Common
            WindowsInstaller = $installedSoftware.WindowsInstaller; # Not Common
            InstallSource    = $installedSoftware.InstallSource;
            InstallDate      = ConvertTo-DateTime $installedSoftware.InstallDate;
            InstallLocation  = $installedSoftware.InstallLocation; # Not Common
            UninstallString  = $installedSoftware.UninstallString;
            HelpTelephone    = $installedSoftware.HelpTelephone; # Not Common
            Contact          = $installedSoftware.Contact; # Not Common
            Language         = $installedSoftware.Language;
            URLUpdateInfo    = $installedSoftware.URLUpdateInfo; # Not Common
            Comments         = $installedSoftware.Comments; # Not Common
            HelpLink         = $installedSoftware.HelpLink; # Not Common
            ModifyPath       = $installedSoftware.ModifyPath; 
            URLInfoAbout     = $installedSoftware.URLInfoAbout; # Not Common
            EstimatedSize    = $installedSoftware.EstimatedSize;
            Publisher        = $installedSoftware.Publisher; 
            Size             = $installedSoftware.Size
        }
    }
   
    Write-Log "Detected $($software.Count) pieces of software on $env:COMPUTERNAME."

    return $software
}

Function Get-AppXSoftware {
    Write-Log "Searching AppX packages."
    try {
        return Get-AppxPackage -AllUsers | ConvertTo-EnumsAsStrings -Depth 4 
    } catch {
        Write-Log "Unable to get AppX packages." 3
        Trace-Error
        return $null
    }
}

Function Get-AppVSoftware {
    Write-Log "Searching AppV packages."
    try {
        return Get-AppvClientPackage -All
    } catch {
        Write-Log "Unable to get AppV packages." 3
        Trace-Error
        return $null
    }
}

Function Get-TPMSettings {
    Write-Log "Getting TPM Settings."
    try {
        return Get-TPM | ConvertTo-EnumsAsStrings
    } catch {
        Write-Log "Unable to get TPM settings." 3
        Trace-Error
        return $null
    }
    
}

Function Get-WMIInfo ($class) {
    Write-Log "Getting information from WMI Object '$class'."
    $exclude = @("Scope", "Path", "Options", "ClassPath", "Properties", "SystemProperties", "__GENUS", "__CLASS", 
        "__SUPERCLASS", "__DYNASTY", "__RELPATH", "__PROPERTY_COUNT", "__DERIVATION" , 
        "__SERVER", "__NAMESPACE", "__PATH", "PSComputerName")
    try {
        return  Get-WmiObject -Class $class | Select-Object -Property * -ExcludeProperty $exclude
    } catch {
        Write-Log "Unable to get WMI object information from $class." 3
        Trace-Error
        return $null
    }
    
}

Function Get-Antivirus {
    Write-Log "Getting antivirus data."
    try {
        return Get-MpComputerStatus | Select-Object -Property * -ExcludeProperty CimClass, CimInstanceProperties, CimSystemProperties, PSComputerName
    } catch {
        Write-Log "Failed to get antivirus information. This may happen if something other than Windows Defender is being used." 3
        return $null
    }
}

Function Get-System {
    Write-Log "Getting System information."
    try {
        $system = Get-WMIInfo Win32_ComputerSystem;
        return $system
    } catch {
        Write-Log "Failed to retrieve system information from Win32_ComputerSystem WMI object." 3
        Trace-Error
        return $null
    }
    
}

Function Get-NetworkInterfaces {
    Write-Log "Getting network interfaces."
    try {
        return Get-NetAdapter | Select-Object -Property * -ExcludeProperty CimClass, CimInstanceProperties, CimSystemProperties, PSComputerName, HigherLayerInterfaceIndices
    } catch {
        Write-Log "Failed to get network interfaces information." 3
        Trace-Error
        return $null
    }
}

Function Get-ActivationStatus {
    Write-Log "Getting Activation Status."

    try {
        $licenseStatus = @{0 = "Unlicensed"; 1 = "Licensed"; 2 = "Out Of Box Grace Period"; 3 = "Out Of Time Grace period"; 4 = "Non-Genuine Grace Period"; 5 = "Notification Period"; 6 = "Extended Grace Period" }
        $ActivationStatus = $licenseStatus[[int]$(Get-WmiObject SoftwareLicensingProduct -Filter "ApplicationID = '55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey like '%'").LicenseStatus]
        return $ActivationStatus
    } catch {
        Write-Log "Failed to get activation status." 3
        Trace-Error
        return $null
    }
   
}

Function Get-Storage {
    Write-Log "Getting storage information."
    try {
        return Get-Volume | Select-Object -Property * -ExcludeProperty CimClass, CimInstanceProperties, CimSystemProperties, PSComputerName
    } catch {
        Write-Log "Failed to get volume information." 3
        Trace-Error
        return $null
    }
}

$ErrorActionPreference = "SilentlyContinue"
Function Get-OperatingSystem {
    Write-Log "Getting Operating System Information."
    try {
        $OperatingSystem = Get-WMIInfo Win32_OperatingSystem
        $osRegDetails = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        $cscReg = Get-ItemProperty "HKLM:\SOFTWARE\CSC\"

        $info = [Ordered]@{
            "Operating System" = $OperatingSystem.Caption;
            "OS Version"       = "$($osRegDetails.ReleaseId)";
            "OS Build"         = "$($osRegDetails.CurrentBuild).$($osRegDetails.UBR)"
            "Service Pack"     = "$($OperatingSystem.ServicePackMajorVersion).$($OperatingSystem.ServicePackMinorVersion)";
            "Computer Name"    = $env:COMPUTERNAME;
            "Architecture"     = $OperatingSystem.OSArchitecture;
            "Build Release"    = $cscReg.BuildRelease;
            "Build Version"    = $cscReg.BuildVersion;
        }
    
        return ConvertTo-Json $info
    } catch {
        Write-Log "Failed to get operating system information." 3
        Trace-Error
        return $null
    }
}

Function Get-HardwareInfo {
    Write-Log "Getting Operating System Information."
    try {
        $ComputerSystem = Get-WMIInfo Win32_ComputerSystem
        $Bios = Get-WMIInfo Win32_BIOS
        $VideoAdapter = Get-WMIInfo Win32_VideoController
        $RAM = [Math]::Round(($ComputerSystem.TotalPhysicalMemory / (1024 * 1024 * 1024)), 2)

        $info = [Ordered]@{
            "Manufacturer" = $ComputerSystem.Manufacturer;
            "Model"        = $ComputerSystem.Model;
            "Serial"       = $Bios.SerialNumber;
            "BIOS Verson"  = $Bios.Name;
            "Video Driver" = $VideoAdapter.Description;
            "Physical RAM" = "$($RAM)GB";
        }
    
        return ConvertTo-Json $info
    } catch {
        Write-Log "Failed to get hardware information." 3
        Trace-Error
        return $null
    }
}

Function ConvertTo-ByteString ($bytes) {

    if (-not $bytes) {
        return $null
    }

    $gb = [Math]::Round(($bytes / 1GB), 2)
    if ($gb -ge 1) {
        return "$($gb)GB"
    }
    $mb = [Math]::Round(($bytes / 1MB), 2)
    if ($mb -ge 1) {
        return "$($mb)MB"
    }
    $kb = [Math]::Round(($bytes / 1KB), 2)
    if ($kb -ge 1) {
        return "$($kb)KB"
    }

    return "$bytes bytes"
}

Function Get-OfflineFilesDiskSpace {
    # $offlineItems = Get-WmiObject -Class Win32_OfflineFilesItem
  
    # $offlineFiles = $offlineItems | ? { $_.ItemType -eq 0 }
    # $files = Get-Item $offlineFiles.ItemPath
   
    # $total = ($files | Measure-Object -Sum Length).Sum
   
   
    # $info = @{
    #     Total = ConvertTo-ByteString $total;
    # }

    $offlineFilesConfig = Get-WmiObject -Class "Win32_OfflineFilesCache"
    $info = [Ordered]@{}
    
    if ($offlineFilesConfig.Active -and $offlineFilesConfig.Enabled) {

        try {
            $comCode = Get-Content "$PSScriptRoot\Csharp\IOfflineFileCache.cs"
            Add-Type -TypeDefinition ($comCode -join "`n")
        } catch {}

        try {
            $output = ([offlinecache]::GetOfflineCache()) 
            $info = [Ordered] @{
                VolumeTotal   = $output[0]
                Limit         = $output[1]
                Used          = $output[2]
                UnpinnedLimit = $output[3]
                UnpinnedUsed  = $output[4]
            }
        } catch {
            Write-Log "Failed to get offline file information."
            Trace-Error
            return $null
        }

    }

    $info["Active"] = $offlineFilesConfig.Active
    $info["Enabled"] = $offlineFilesConfig.Enabled
    return $info;
}

Function Get-DiskSpace {

    try {
        $volumes = Get-WMIInfo Win32_LogicalDisk
        $cDrive = $volumes | ? { $_.DeviceID -eq "C:" }
        $hDrive = $volumes | ? { $_.DeviceID -eq "H:" }
        
        $info = [Ordered]@{
            "C: Size"           = "$([Math]::Round(($cDrive.Size / 1GB),2))GB";
            "C: Size Remaining" = "$([Math]::Round(($cDrive.FreeSpace / 1GB),2))GB";
        }

        if ($hDrive) {
            $info["H: Size"] = ConvertTo-ByteString $hDrive.Size;
            $info["H: Size Remaining"] = ConvertTo-ByteString $hDrive.FreeSpace
        } else {
            $info["H: Drive"] = "Not Found"
        }

        $offlineFilesInfo = Get-OfflineFilesDiskSpace
        $info["Offline Files Enabled"] = $offlineFilesInfo.Enabled
        $info["Offline Files Active"] = $offlineFilesInfo.Active
        
        if ($offlineFilesInfo.Active -and $offlineFilesInfo.Enabled) {
            $info["Offline Files Size"] = ConvertTo-ByteString $offlineFilesInfo.Used
            $info["Offline Files Size Remaining"] = ConvertTo-ByteString ($offlineFilesInfo.Limit - $offlineFilesInfo.Used)
        }

        return ConvertTo-Json $info
    } catch {
        Write-Log "Failed to get disk space information." 3
        Trace-Error
        return $null
    }
    
}

Function Start-EmptyRecycleBin {
    try{
        Clear-RecycleBin -Force
        $notice = @{
            state = "success";
            message= "Recycle bin cleared succssfully."
        }
        return $notice | ConvertTo-Json
    } catch {
        $notice = @{
            state = "error";
            message="Recycle bin was unable to be cleared."
        }
    }
}

Function Get-IPInfo {
    $netAdapterConfigs = Get-WmiObject -Query "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE"
    $netAdapters = @()
    foreach ($config in $netAdapterConfigs) {
        try {
            $netAdapter = Get-WmiObject -Query "SELECT * FROM Win32_NetworkAdapter WHERE MACAddress = '$($config.MACAddress)' AND NetConnectionID <> NULL"
            $netAdapters += [Ordered]@{
                "Name"            = $netAdapter.NetConnectionID;
                "IPv4"            = $config.IPAddress[0];
                "IPv6"            = $config.IPAddress[1];
                "Subnet Mask"     = $config.IPSubnet[0];
                "Default Gateway" = $config.DefaultIPGateway;
                "DNS Domain"      = $config.DNSDomain;
            }
        } catch {
            Write-Log "Error occured adding netadapter."
            Trace-Error
        }
    }

    return ConvertTo-Json $netAdapters
}

Function Get-NICInfo {
    $interfaces = Get-WmiObject -Query "SELECT * from Win32_NetworkAdapter WHERE NetConnectionID <> Null AND MACAddress <> Null"
    $info = @()

    foreach ($interface in $interfaces) {
        try {
            $info += [Ordered]@{
                "Name"        = $interface.NetConnectionID;
                "Card"        = $interface.ProductName;
                "MAC Address" = $interface.MACAddress;
            }
        } catch {
            Trace-Error
        }
        
    }

    return ConvertTo-Json $info
}

function Get-ADSystemInfo {
    <#
        .LINK
            https://technet.microsoft.com/en-us/library/ee198776.aspx
    #>
    $properties = @(
        'UserName',
        'ComputerName',
        'SiteName'
        # 'DomainShortName',
        # 'DomainDNSName',
        # 'ForestDNSName',
        # 'PDCRoleOwner',
        # 'SchemaRoleOwner',
        # 'IsNativeMode'
    )
    $ads = New-Object -ComObject ADSystemInfo
    # $ads = Import-CliXML "C:\Users\dwild8\Documents\VsCode\ComputerDetailsElectron\Test\ADSystemInfo.xml"
    $type = $ads.GetType()
    $hash = @{}
    foreach ($p in $properties) {
        try {
            $hash.Add($p, $type.InvokeMember($p, 'GetProperty', $Null, $ads, $Null))
        } catch {
            Write-Log "Failed to get property $p." 3
            Trace-Error
        }
    }

    $domain, $user = (whoami).split("[\|+]")

    $info = [Ordered]@{
        "User OU"      = ConvertTo-FriendlyOUString $hash.UserName;
        "Computer OU"  = ConvertTo-FriendlyOUString $hash.ComputerName;
        "Site Name"    = $hash.SiteName;
        "Username"     = $user;
        "Logon Domain" = $domain;
        "Logon Server" = $env:LOGONSERVER -replace "^\\\\", ""
    }

    return $info | ConvertTo-Json
}

Function ConvertTo-FriendlyOUString($LDAP) {
    $list = $LDAP -split ",[a-zA-Z0-9]*?="
    $list = $list[1..$list.length]
    # [array]::reverse($list)
    return $list -join "\"
}

Function Get-AllData {
    $publicDesktop = [Environment]::GetFolderPath("Desktop");
    $file = "$publicDesktop\$env:COMPUTERNAME Computer Details.txt"
    Set-Content $file ""

    try {
        Remove-TypeData "System.Array" -ErrorAction SilentlyContinue
    } catch {
        Write-Log "Error trying to remove data type."
    }
    

    Function Add-String($string) {
        $string | Out-File $file -Append -Encoding ASCII
    }

    $info = [Ordered]@{
        "Operating System"     = ConvertFrom-Json (Get-OperatingSystem);
        "Hardware Information" = ConvertFrom-Json (Get-HardwareInfo);
        "User"                 = ConvertFrom-Json (Get-ADSystemInfo);
        "Disk Space"           = ConvertFrom-Json (Get-DiskSpace);
        "IP Information"       = ConvertFrom-Json (Get-IPInfo);
        "NIC"                  = ConvertFrom-Json (Get-NICInfo);
    }

    $introduction = "This file details a report for the machine $env:COMPUTERNAME from the Computer Details program. All details from the program are output in this report.`n"

    Add-String $introduction
    Add-String "This report was generated on $(Get-Date)."

    $divider = "================================================================================="
    foreach ($key in $info.Keys) {
        Add-String $divider
        Add-String $key
        Add-String $divider
        Add-String $info[$key]
    }

    return $info | ConvertTo-Json 
}

Function Get-RegValues ($location) {
    Write-Log "Getting registry values from '$location'."
    try {
        if (Test-Path $location) {
            $keys = Get-ChildItem $location -Recurse | Get-ItemProperty | Select-Object -Property * -Exclude PSProvider
            $keys += Get-Item $location | Get-ItemProperty | Select-Object -Property * -Exclude PSProvider
    
            foreach ($key in $keys) {
                $key.PsPath = $key.PsPath.Replace("Microsoft.PowerShell.Core\Registry::", "")
                $key.PSParentPath = $key.PSParentPath.Replace("Microsoft.PowerShell.Core\Registry::", "")
            }

            return $keys
        } else {
            Write-Log "Cannot find registry key $location. Therefore cannot fetch any values."
            return $null
        }
    } catch {
        Write-Log "Failed to get registry information for $location." 3
        Trace-Error
        return $null
    }
}

Function Get-BitLocker {
    Write-Log "Getting BitLocker information."
    try {
        $bitlocker = Get-BitLockerVolume
        return $bitlocker | ConvertTo-EnumsAsStrings -Depth 4
    } catch {
        Write-Log "Failed to get BitLocker information." 3
        Trace-Error
        return $null
    }
}

Function Get-Logs {
    Write-Log "Getting event logs."
    $events = @(
        @{ # Application Fault
            LogName      = "Application";
            ProviderName = "Application Error";
            ID           = 1000;
        }, 
        @{ # Service Failed to Restart
            LogName      = "System";
            ProviderName = "Service Control Manager";
            ID           = 7000;
        }, 
        @{ # Application Hang
            LogName      = "Application";
            ProviderName = "Application Hang";
            ID           = 1002;
        }, 
        @{ # Service Timeout
            LogName      = "System";
            ProviderName = "Service Control Manager";
            ID           = 7009;
        },
        @{ # Windows Update Failure
            LogName      = "System";
            ProviderName = "Microsoft-Windows-WindowsUpdateClient";
            ID           = 20;
        },
        @{ # Scheduled Task Delayed or Failed
            LogName = "Microsoft-Windows-TaskScheduler/Operational";
            ID      = 201;
        },
        @{ # Unexpected Reboot
            LogName      = "System";
            ProviderName = "Microsoft-Windows-Kernel-Power";
            ID           = 41;
        },
        @{ # System Logs Critical
            LogName = "System";
            Level   = 1;
        },
        @{ # Application Logs Critical
            LogName = "Application";
            Level   = 1;
        }
    )

    $end = Get-Date
    $start = (Get-Date).AddMonths(-6)

    foreach ($event in $events) {
        $event.StartTime = $start
        $event.EndTime = $end
    }

    try {
        return Get-WinEvent -FilterHashtable $events 
    } catch [NoMatchingEventsFound] {
        Write-Log "Didn't find any windows events matching specified criteria."
        return $null
    } catch {
        Write-Log "Failed to retrieve Windows events, from event viewer."
        Trace-Error
        return $null
    }
    
}

Function Get-RootCertificates {
    Write-Log "Getting root certificates."
    return Get-Certificates Cert:\LocalMachine\Root
}

Function Get-DirectAccessCertificates {
    Write-Log "Getting direct access certificates."
    return Get-Certificates Cert:\LocalMachine\My
}

Function Get-Certificates ($location) {
    if (Test-Path $location) {
        try {
            return Get-ChildItem $location | Select-Object -Property * -ExcludeProperty PSDrive, PSProvider, PSChildName, PSPath, PSParentPath
        } catch {
            Write-Log "Failed to get certificate data from '$location'."
            Trace-Error
            return $null
        }
    } else {
        Write-Log "Could not find location '$location' to retrieve any certificate data"
    }
}

Function ConvertTo-DateTime([string]$dateString) {
    switch -Regex ($dateString) {

        "^\d{14}\.\d{6}\+\d{3}$" {
            $dateArgs = @{Year = $date.SubString(0, 4); Month = $date.SubString(4, 2); Day = $date.SubString(6, 2); Hour = $date.SubString(8, 2); Minute = $date.SubString(10, 2) }
            $date = Get-Date @dateArgs
            return $date | Select-Object -Property *
        }

        "^\d{8}$" {
            $dateArgs = @{Year = $dateString.SubString(0, 4); Month = $dateString.SubString(4, 2); Day = $dateString.SubString(6, 2); }
            $date = Get-Date @dateArgs
            return $date | Select-Object -Property *
        }

        default {
            try {
                return ([DateTime]$dateString) | Select-Object -Property *
            } catch {
                return $null
            }
        }
    }
}

Function Get-MSInfo32 {
    Write-Log "Getting MSInfo32 info."
    $MSInfo32 = Get-ComputerInfo
    if (-not $MSInfo32) {
        $MSInfo32 = @{}
    }
    $MSInfo32 = $MSInfo32 | ConvertTo-EnumsAsStrings -Depth 4

    if (-not $MSInfo32.CsDNSHostName) {
        $computerInfo = Get-WMIInfo Win32_ComputerSystem
        $properties = $computerInfo | Get-Member | ? { $_.MemberType -eq "NoteProperty" }
        foreach ($prop in $properties) {
            $propName = $prop.Name
            $MSInfo32["Cs$propName"] = $computerInfo.$propName
        }
    }

    if (-not $MSInfo32.CsProcessors) {
        $MSInfo32.CsProcessors = Get-WMIInfo Win32_Processor | ConvertTo-EnumsAsStrings -Depth 4
        if ($MSInfo32.CsProcessors.GetType().Name -ne "Object[]") { $MSInfo32.CsProcessors = @($MSInfo32.CsProcessors) }
        foreach ($processor in $MSInfo32.CsProcessors) {
            $processor.Availability = ([CPUAvailability]$processor.Availability).ToString()
            $processor.CpuStatus = ([CPUStatus]$processor.CpuStatus).ToString()
        }
    }

    return $MSInfo32
}

Function Get-WindowsCapabailities {
    Write-Log "Getting Windows capabilities."
    try {
        return Get-WindowsCapability -Online  | ConvertTo-EnumsAsStrings -Depth 4
    } catch {
        Write-Log "Unable to get Windows capabilities." 3
        Trace-Error
        return $null
    }
}

Function Get-FirewallRules {
    Write-Log "Getting firewall rules."
    try {
        return Get-NetFirewallRule | Select-Object -Property * -ExcludeProperty CimClass, CimInstanceProperties, CimSystemProperties, PSComputerName | ConvertTo-EnumsAsStrings
    } catch {
        Write-Log "Unable to get firewall rules." 3
        Trace-Error
        return $null
    }
}

Function Get-FirewallProfiles {
    Write-Log "Getting firewall profiles."
    try {
        return Get-NetFirewallProfile | Select-Object -Property * -ExcludeProperty CimClass, CimInstanceProperties, CimSystemProperties | ConvertTo-EnumsAsStrings
    } catch {
        Write-Log "Unable to get firewall profiles." 3
        Trace-Error
        return $null
    }
}

Filter ConvertTo-EnumsAsStrings ([int] $Depth = 2, [int] $CurrDepth = 0) {
    if ($_.Count -eq 0) {
        return $_
    }
    if ($_ -is [enum]) {
        # enum value -> convert to symbolic name as string
        $_.ToString() 
    } elseif ($null -eq $_ -or $_.GetType().IsPrimitive -or $_ -is [string] -or $_ -is [decimal] -or $_ -is [datetime] -or $_ -is [datetimeoffset]) {
        $_
    } elseif ($_ -is [Collections.IEnumerable]) {
        , ($_ | ConvertTo-EnumsAsStrings -Depth $Depth -CurrDepth ($CurrDepth + 1))
    } else {
        # non-primitive type -> recurse on properties
        if ($CurrDepth -gt $Depth) {
            # depth exceeded -> return .ToString() representation
            "$_"
        } else {
            $oht = [ordered] @{}
            foreach ($prop in $_.psobject.properties) {
                if ($prop.Value -is [Collections.IEnumerable] -and -not $prop.Value -is [string]) {
                    $oht[$prop.Name] = @($prop.Value | ConvertTo-EnumsAsStrings -Depth $Depth -CurrDepth ($CurrDepth + 1))
                } else {      
                    $oht[$prop.Name] = $prop.Value | ConvertTo-EnumsAsStrings -Depth $Depth -CurrDepth ($CurrDepth + 1)
                }
            }
            $oht
        }
    }
}

Function Get-PowerConfig { 
    Write-Log "Getting power settings."
    try {
        $powerSettingsString = powercfg /q
    } catch {
        Write-Log "Unable to get power configuration settings." 3
        Trace-Error
        return $null
    }
    

    Enum States {
        SCHEME = 1; POWER_SETTING = 2; SUB_GROUP = 3; POWER_OPTIONS = 4
    }

    $state = ""
    $scheme = $null
    $subgroup = $null
    $powerSetting = $null    
    $schemes = @()

    foreach ($line in ($powerSettingsString | Select-String '.')) {

        switch -Regex ($line) {
            "Power Scheme GUID: (?<GUID>.*)  \((?<Scheme>.*)\)" {

                if ($scheme) {
                    $schemes += $scheme
                }

                $scheme = @{
                    Name      = $matches.Scheme;
                    GUID      = $matches.GUID;
                    SubGroups = @();
                }   

                $state = [States]::SCHEME
                break
            }
            
            "Subgroup GUID: (?<GUID>.*)  \((?<Subgroup>.*)\)" {
                
                if ($subgroup) {
                    $scheme.Subgroups += $subgroup
                }
                
                $subgroup = @{
                    GUID     = $matches.GUID;
                    Name     = $matches.Subgroup;
                    Settings = @();
                }

                $state = [States]::SUB_GROUP
                break
            }

            "Power Setting GUID: (?<GUID>.*)  \((?<PowerSetting>.*)\)" {

                if ($powerSetting) {
                    $subgroup.Settings += $powerSetting;
                }

                $powerSetting = @{
                    GUID = $matches.GUID;
                    Name = $matches.PowerSetting;
                }

                $state = [States]::POWER_SETTING
                break
            }

            "GUID Alias: (?<Alias>.*)" {
                switch ($state) {
                    ([States]::SCHEME) {
                        $scheme.Alias = $matches.Alias
                    }
                    ([States]::SUB_GROUP) {
                        $subgroup.Alias = $matches.Alias
                    }
                    ([States]::POWER_SETTING) {
                        $powerSetting.Alias = $matches.Alias
                    }
                }
                break
            }

            "Minimum Possible Setting: (?<Min>.*)" {
                $powerSetting.Minimum = $matches.Min
                break
            }

            "Maximum Possible Setting: (?<Max>.*)" {
                $powerSetting.Maximum = $matches.Max
                break
            }

            "Possible Setting Friendly Name: (?<Name>.*)" {
                if ($options) {
                    $options += $matches.Name
                } else {
                    $options = @($matches.Name)
                }
                break
            }

            "Possible Settings increment: (?<Increment>.*)" {
                $powerSetting.Increment = $matches.Increment
                break
            }

            "Possible Settings units: (?<Unit>.*)" {
                $powerSetting.Unit = $matches.Unit
                break
            }

            "Current AC Power Setting Index: (?<ACValue>.*)" {
                if ($options) {
                    $powerSetting.ACValue = $options[$matches.ACValue]
                } else {
                    $powerSetting.ACValue = $matches.ACValue
                }
                break
            }

            "Current DC Power Setting Index: (?<DCValue>.*)" {
                if ($options) {
                    $powerSetting.DCValue = $options[$matches.DCValue]
                } else {
                    $powerSetting.DCValue = $matches.DCValue
                }

                $subgroup.Settings += $powerSetting
                $powerSetting = $null
                $options = $null
                break
            }
        }
        
    }

    return $scheme
}

Function New-Zip ($folder) {
    Write-Log "Compressing '$folder' into '$folder.zip'"
    $compress = @{
        Path        = $folder;
        Destination = "$folder.zip";
    }

    Compress-Archive @compress -Force
    if (Test-Path "$folder.zip") {
        Write-Log "Successfully created $folder.zip."
    }
}

Function Send-Email ($Recipients, $Subject, $Body, $reportFolder) {
    Write-Log "Preparing to email device report."
    Write-Log "Connecting to Outlook."
    $Outlook = New-Object -ComObject Outlook.Application
    Write-Log "Creating email."
    $Mail = $Outlook.CreateItem(0)

    Write-Log "Adding attachments."
    # https://docs.microsoft.com/en-gb/office/vba/outlook/how-to/items-folders-and-stores/attach-a-file-to-a-mail-item
    New-Zip $reportFolder
    $attachments = $Mail.Attachments
    $attachments.Add("$reportFolder.zip")

    Write-Log "Adding recipients."
    foreach ($recipient in $Recipients) {
        $Mail.Recipients.Add($recipient)
    }

    Write-Log "Creating email contents."
    $Mail.Subject = $Subject
    $Mail.Body = $Body

    Write-Log "Sending email to Outlook to deliver."
    $Mail.Send()

    Write-Log "Exiting Outlook and cleaning resources."
    $Outlook.Quit()
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Outlook) | Out-Null
    Write-Log "Outlook resources cleared."
}

Function Get-GPO {
    Write-Log "Getting GPO Results"
    $folder = $env:PUBLIC
    $fileName = "$env:COMPUTERNAME.xml"
    $fileLocation = "$folder/$fileName"
    try {
        gpresult /f /scope computer /x $fileLocation
    
        [XML]$xml = (Get-Content $fileLocation)
        $rsop = $xml.Rsop
        $hash = (ConvertTo-HashFromXML -Node $rsop.ComputerResults).Value

        Remove-Item $fileLocation -Force 
        return $hash
    } catch {
        Write-Log "Unable to get GPO data from gpresult.exe." 3
        Trace-Error
        return $null
    }
}

Function ConvertTo-HashFromXML($node) {
    $children = $node.ChildNodes
    if ($children.Count -gt 0 -and -not ($children[0].GetType().Name -eq "XmlText")) {
        $parentHash = @{}
        foreach ($child in $children) {
            $result = ConvertTo-HashFromXML $child
            $childNode = $parentHash."$($result.Name)"
            if ($childNode) {
                if ($childNode.GetType().Name -eq "Object[]") {
                    $parentHash."$($result.Name)" += $result.Value
                } else {
                    $list = @($childNode, $result.Value)
                    $parentHash."$($result.Name)" = $list
                }
            } else {
                $parentHash."$($result.Name)" = $result.Value
            }
        }
        return @{
            Name  = $node.LocalName; 
            Value = $parentHash; 
        }
    } else {
        return @{
            Name  = $node.LocalName;
            Value = $node.InnerText;
        }
    }
    
}
Function Get-Ivanti {
    Write-Log "Getting Ivanti information."

    $ivantiServiceName = "Ivanti Device and Application Control Command and Control"
    $ivantiProcessName = "RTNotify"
    $serverRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\scomc\Parameters"
    $sxDataFilesPath = "C:\Windows\sxdata"

    $ivantiService = Get-Service | ? { $_.DisplayName -eq $ivantiServiceName } 

    $sxPublicKeyExists = Test-Path "C:\Windows\sxdata\sx-public.key" 

    $ivantiProcess = Get-Process | ? { $_.ProcessName -eq $ivantiProcessName } 

    if (Test-Path $serverRegPath) {
        $ivantiServers = Get-ItemPropertyValue $serverRegPath -Name "Servers" 
        $ivantiServers = if ($ivantiServers) { $ivantiServers.split(" ") } 
        $serverPings = @() 

        foreach ($server in $ivantiServers) { 
            $serverPings += @{ 
                Server = $server; 
                Ping   = Test-Connection ($server -replace ":.*", "") -Quiet; 
            } 
        } 
    } 

    $lastUpdatedTimeSpan = $null 
    if (Test-Path $sxDataFilesPath) {
        $sxDataFiles = Get-ChildItem $sxDataFilesPath 
        $potentialIssue = $false 

        foreach ($file in $sxDataFiles) {
            if ($file.Name -match ".cch$") {
                $lastUpdatedTimeSpan = (Get-Date) - $file.LastWriteTime 
                if ($lastUpdatedTimeSpan.Day -gt 14) { 
                    $potentialIssue = $true 
                } 
            }
        }
    }

    $ivanti = @{
        ServiceStatus             = $ivantiService.Status;
        PublicKeyExists           = $sxPublicKeyExists;
        ProcessRunning            = ($null -ne $ivantiProcess);
        ServerPings               = $serverPings;
        CCHPermissionsLastUpdated = $lastUpdatedTimeSpan;
    }

    return $ivanti
}









Function Show-BalloonTip {
    <# 
        .SYNOPSIS 
        This Function Produces a balloon tip in the system tray for the amount of time designated.
             
        .DESCRIPTION 
        This Function Produces a balloon tip in the system tray for the amount of time designated.
     
        .PARAMETER BalloonTipText
            The Message to be displayed in the balloon tip. 
     
        .PARAMETER BalloonTipTitle 
            The Title of the balloon tip. 
     
        .PARAMETER BalloonTipIcon
            The type of balloon tip icon to display. 
            Valid Types are:  
                Error       - The balloon tip contains a symbol consisting of white X in 
                                a circle with a red background. 
                Information - The balloon tip contains a symbol consisting of a lowercase 
                                letter i in a circle. 
                None        - The balloon tip contain no symbols. 
                Warning     - The balloon tip contains a symbol consisting of an exclamation 
                                point in a triangle with a yellow background. 
            Reference: 
            https://docs.microsoft.com/en-us/dotnet/api/system.windows.forms.notifyicon.balloontipicon  
     
        .PARAMETER BalloonTipTime 
            The time interval [int32] in miliseconds to show the balloon tip.
     
            Reference: 
            https://docs.microsoft.com/en-us/dotnet/api/system.windows.forms.notifyicon.showballoontip 
    
        .PARAMETER EnableSound
            Produces a sound when balloon tip is displayed to attract attention to tip.
     
        .EXAMPLE
        Show-BalloonTip -BalloonTipText "Balloon Tip Information Text." -BalloonTipTitle "Balloon Tip Information Title." -BalloonTipIcon Info -BalloonTipTime 1500
    
        .EXAMPLE
        Show-BalloonTip -BalloonTipText "Balloon Tip Error Text." -BalloonTipTitle "Balloon Tip Error Title." -BalloonTipIcon Error -BalloonTipTime 1500
     
        .EXAMPLE
        Show-BalloonTip -BalloonTipText "Balloon Tip Warning Text." -BalloonTipTitle "Balloon Tip Warning Title." -BalloonTipIcon Warning -BalloonTipTime 1500
    
        .EXAMPLE
        Show-BalloonTip -BalloonTipText "Balloon Tip Text." -BalloonTipTitle "Balloon Tip Title." -BalloonTipTime 1500
    #>  
        Param(
            [Parameter(Mandatory = $true, Position = 0)]
            [ValidateNotNull()]
            [String]
            $BalloonTipText,
            [Parameter(Position = 1)]
            [String]
            $BalloonTipTitle = 'Tip',
            [Parameter(Position = 2)]
            [ValidateSet('Error', 'Info', 'None', 'Warning')]
            [String]
            $BalloonTipIcon = 'None',
            [Parameter(Position = 3)]
            [Int]
            $BalloonTipTime = 1000
        )
        end {
            Add-Type -AssemblyName System.Windows.Forms
            Add-Type -AssemblyName System.Drawing
            [Windows.Forms.ToolTipIcon]$BalloonTipIcon = $BalloonTipIcon
            $ContextMenu = New-Object System.Windows.Forms.ContextMenu
            $MenuItem = New-Object System.Windows.Forms.MenuItem
    
            $NotifyIcon = New-Object Windows.Forms.NotifyIcon -Property @{
                BalloonTipIcon = $BalloonTipIcon
                BalloonTipText = $BalloonTipText
                BalloonTipTitle = $BalloonTipTitle
                ContextMenu = $ContextMenu
                Icon = [Drawing.Icon]::ExtractAssociatedIcon((Get-Command powershell).Path)
                Text = -join $BalloonTipText[0..62]
                Visible = $false
            }
            $NotifyIcon.contextMenu.MenuItems.AddRange($MenuItem)
            $NotifyIcon.Visible = $True
            $MenuItem.Text = "Exit"
            $MenuItem.add_Click({
               $NotifyIcon.Visible = $false
               $NotifyIcon.ShowInTaskbar = $false
            })
            $NotifyIcon.ShowBalloonTip($BalloonTipTime)     
            switch ($Host.Runspace.ApartmentState) {
                STA {
                    $null = Register-ObjectEvent -InputObject $NotifyIcon -EventName BalloonTipClosed -Action {                     
                        $Sender.Dispose()
                        Unregister-Event $EventSubscriber.SourceIdentifier
                        Remove-Job $EventSubscriber.Action
                    }
                }
                default {
                    continue
                }
            }
        }
    }
    