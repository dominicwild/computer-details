enum CPUArchitecture {
    x86; MIPS; Alpha; PowerPC; ARM; ia64; x64 = 9;
}

enum CPUAvailability {
    Other = 1; Unknown; RunningOrFullPower; Warning; InTest; NotApplicable; 
    PowerOff; OffLine; OffDuty; Degraded; NotInstalled; InstallError; 
    PowerSaveUnknown; PowerSaveLowPower; PowerSaveStandby; PowerCycle; 
    PowerSaveWarning; Paused; NotReady; NotConfigured; Quiesced;
}
 
enum CPUStatus {
    Unknown;Enabled;DisabledByUserFromBIOS;DisabledByBIOS;Idle;Reserved1;Reserved2;Other
}

Function ConvertTo-SplitOnCapitalLetters($string) {
    $split = $string -csplit "([A-Z][a-z]+)" | ? { $_ }
    return $split -join " "
}

# class EnumToString {
#     static [string]toString([ProcessorAvailability]$enum) {
#         $string = Switch ($enum) {
#             "RunningFullPower" {
#                 "Running / Full Power"
#             }
#             "InTest" {
#                 "In Test"
#             }
#             "NotApplicable" {
#                 "Not Applicable"
#             }
#             "PowerOff" {
#                 "Power Off"
#             }
#             "OffLine" {
#                 "Off Line"
#             }
#             "OffDuty" {
#                 "Off Duty"
#             }
#             "NotInstalled" {
#                 "Not Installed"
#             }
#             "InstallError" {
#                 "Install Error"
#             }
#             "PowerSaveUnknown" {
#                 "Power Save Unknown"
#             }
#             "PowerSaveLowPower" {
#                 "Power Save Lower Power"
#             }
#             "PowerSaveStandby" {
#                 "Power Save Standby"
#             }
#             "PowerCycle" {
#                 "Power Cycle"
#             }
#             "PowerSaveWarning" {
#                 "Power Save Warning"
#             }
#             "NotReady" {
#                 "Not Ready"
#             }
#             "NotConfigured" {
#                 "Not Configured"
#             }
#             default {
#                 $null
#             }
#         }
#         if ($string) {
#             return $string
#         } else {
#             return [string]$enum
#         }
#     }
# }
