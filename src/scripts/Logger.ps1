Param (
    $logFile = "log.log",
    $logFolder = $PSScriptRoot,
    $logStyle = "Legacy",
    $compress = $false,
    $logTempFolder = $logFolder,
    $logName = $logFile,
    $logMaxSize = 10000000,
    $writeToHost = $true,
    $debugMessage = "Debug",
    $phase = "Default"
)

$error.clear()

Function Write-Log {
    <#
        .SYNOPSIS
            Write messages to a log file in CMTrace.exe compatible format or Legacy text file format.
        .DESCRIPTION
            Write messages to a log file in CMTrace.exe compatible format or Legacy text file format and optionally display in the console.
        .PARAMETER Message
            The message to write to the log file or output to the console.
        .PARAMETER Severity
            Defines message type. When writing to console or CMTrace.exe log format, it allows highlighting of message type.
            Options: 1 = Information (default), 2 = Warning (highlighted in yellow), 3 = Error (highlighted in red)
        .PARAMETER Source
            The source of the message being logged.
        .PARAMETER ScriptSection
            The heading for the portion of the script that is being executed. Default is: $script:installPhase.
        .PARAMETER LogType
            Choose whether to write a CMTrace.exe compatible log file or a Legacy text log file.
        .PARAMETER LogFileDirectory
            Set the directory where the log file will be saved.
        .PARAMETER LogFileName
            Set the name of the log file.
        .PARAMETER MaxLogFileSizeMB
            Maximum file size limit for log file in megabytes (MB). Default is 10 MB.
        .PARAMETER WriteHost
            Write the log message to the console.
        .PARAMETER ContinueOnError
            Suppress writing log message to console on failure to write message to log file. Default is: $true.
        .PARAMETER PassThru
            Return the message that was passed to the function
        .PARAMETER DebugMessage
            Specifies that the message is a debug message. Debug messages only get logged if -LogDebugMessage is set to $true.
        .PARAMETER LogDebugMessage
            Debug messages only get logged if this parameter is set to $true in the config XML file.
        .EXAMPLE
            Write-Log -Message "Installing patch MS15-031" -Source 'Add-Patch' -LogType 'CMTrace'
        .EXAMPLE
            Write-Log -Message "Script is running on Windows 8" -Source 'Test-ValidOS' -LogType 'Legacy'
        .NOTES
        .LINK
            http://psappdeploytoolkit.com
        #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [AllowEmptyCollection()]
        [Alias('Text')]
        [string[]]$Message,
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateRange(1, 3)]
        [int16]$Severity = 1,
        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateNotNull()]
        [string]$Source = '',
        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateNotNullorEmpty()]
        [string]$ScriptSection = $script:phase,
        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateSet('CMTrace', 'Legacy')]
        [string]$LogType = $logStyle,
        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateNotNullorEmpty()]
        [string]$LogFileDirectory = $(If ($compress) { $logTempFolder } Else { $logFolder }),
        [Parameter(Mandatory = $false, Position = 6)]
        [ValidateNotNullorEmpty()]
        [string]$LogFileName = $logName,
        [Parameter(Mandatory = $false, Position = 7)]
        [ValidateNotNullorEmpty()]
        [decimal]$MaxLogFileSizeMB = $logMaxSize,
        [Parameter(Mandatory = $false, Position = 8)]
        [ValidateNotNullorEmpty()]
        [boolean]$WriteHost = $writeToHost,
        [Parameter(Mandatory = $false, Position = 9)]
        [ValidateNotNullorEmpty()]
        [boolean]$ContinueOnError = $true,
        [Parameter(Mandatory = $false, Position = 10)]
        [switch]$PassThru = $false,
        [Parameter(Mandatory = $false, Position = 11)]
        [switch]$DebugMessage = $false,
        [Parameter(Mandatory = $false, Position = 12)]
        [boolean]$LogDebugMessage = $debugMessage
    )
        
    Begin {
        ## Get the name of this function
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        
        ## Logging Variables
        #  Log file date/time
        [string]$LogTime = (Get-Date -Format 'HH\:mm\:ss.fff').ToString()
        [string]$LogDate = (Get-Date -Format 'dd/MM/yyyy').ToString()
        If (-not (Test-Path -LiteralPath 'variable:LogTimeZoneBias')) { [int32]$script:LogTimeZoneBias = [timezone]::CurrentTimeZone.GetUtcOffset([datetime]::Now).TotalMinutes }
        [string]$LogTimePlusBias = $LogTime + $script:LogTimeZoneBias
        #  Initialize variables
        [boolean]$ExitLoggingFunction = $false
        If (-not (Test-Path -LiteralPath 'variable:DisableLogging')) { $DisableLogging = $false }
        #  Check if the script section is defined
        [boolean]$ScriptSectionDefined = [boolean](-not [string]::IsNullOrEmpty($ScriptSection))
        #  Get the file name of the source script
        Try {
            If ($script:MyInvocation.Value.ScriptName) {
                [string]$ScriptSource = Split-Path -Path $script:MyInvocation.Value.ScriptName -Leaf -ErrorAction 'Stop'
            } Else {
                [string]$ScriptSource = Split-Path -Path $script:MyInvocation.MyCommand.Definition -Leaf -ErrorAction 'Stop'
            }
        } Catch {
            $ScriptSource = ''
        }
        
        ## Create script block for generating CMTrace.exe compatible log entry
        [scriptblock]$CMTraceLogString = {
            Param (
                [string]$lMessage,
                [string]$lSource,
                [int16]$lSeverity
            )
            "<![LOG[$lMessage]LOG]!>" + "<time=`"$LogTimePlusBias`" " + "date=`"$LogDate`" " + "component=`"$lSource`" " + "context=`"$([Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + "type=`"$lSeverity`" " + "thread=`"$PID`" " + "file=`"$ScriptSource`">"
        }
        
        ## Create script block for writing log entry to the console
        [scriptblock]$WriteLogLineToHost = {
            Param (
                [string]$lTextLogLine,
                [int16]$lSeverity
            )
            If ($WriteHost) {
                #  Only output using color options if running in a host which supports colors.
                If ($Host.UI.RawUI.ForegroundColor) {
                    Switch ($lSeverity) {
                        3 { Write-Host -Object $lTextLogLine -ForegroundColor 'Red' -BackgroundColor 'Black' }
                        2 { Write-Host -Object $lTextLogLine -ForegroundColor 'Yellow' -BackgroundColor 'Black' }
                        1 { Write-Host -Object $lTextLogLine }
                    }
                }
                #  If executing "powershell.exe -File <filename>.ps1 > log.txt", then all the Write-Host calls are converted to Write-Output calls so that they are included in the text log.
                Else {
                    Write-Output -InputObject $lTextLogLine
                }
            }
        }
        
        ## Exit function if it is a debug message and logging debug messages is not enabled in the config XML file
        If (($DebugMessage) -and (-not $LogDebugMessage)) { [boolean]$ExitLoggingFunction = $true; Return }
        ## Exit function if logging to file is disabled and logging to console host is disabled
        If (($DisableLogging) -and (-not $WriteHost)) { [boolean]$ExitLoggingFunction = $true; Return }
        ## Exit Begin block if logging is disabled
        If ($DisableLogging) { Return }
        ## Exit function function if it is an [Initialization] message and the toolkit has been relaunched
        If (($AsyncToolkitLaunch) -and ($ScriptSection -eq 'Initialization')) { [boolean]$ExitLoggingFunction = $true; Return }
        
        ## Create the directory where the log file will be saved
        If (-not (Test-Path -LiteralPath $LogFileDirectory -PathType 'Container')) {
            Try {
                $null = New-Item -Path $LogFileDirectory -Type 'Directory' -Force -ErrorAction 'Stop'
            } Catch {
                [boolean]$ExitLoggingFunction = $true
                #  If error creating directory, write message to console
                If (-not $ContinueOnError) {
                    Write-Host -Object "[$LogDate $LogTime] [${CmdletName}] $ScriptSection :: Failed to create the log directory [$LogFileDirectory]. `n$(Resolve-Error)" -ForegroundColor 'Red'
                }
                Return
            }
        }
        
        ## Assemble the fully qualified path to the log file
        [string]$LogFilePath = Join-Path -Path $LogFileDirectory -ChildPath $LogFileName
    }
    Process {
        ## Exit function if logging is disabled
        If ($ExitLoggingFunction) { Return }
        
        ForEach ($Msg in $Message) {
            ## If the message is not $null or empty, create the log entry for the different logging methods
            [string]$CMTraceMsg = ''
            [string]$ConsoleLogLine = ''
            [string]$LegacyTextLogLine = ''
            If ($Msg) {
                #  Create the CMTrace log message
                If ($ScriptSectionDefined) { [string]$CMTraceMsg = "[$ScriptSection] :: $Msg" }
        
                #  Create a Console and Legacy "text" log entry
                [string]$LegacyMsg = "[$LogDate $LogTime]"
                If ($ScriptSectionDefined) { [string]$LegacyMsg += " [$ScriptSection]" }
                If ($Source) {
                    [string]$ConsoleLogLine = "$LegacyMsg [$Source] :: $Msg"
                    Switch ($Severity) {
                        3 { [string]$LegacyTextLogLine = "$LegacyMsg [$Source] [Error] :: $Msg" }
                        2 { [string]$LegacyTextLogLine = "$LegacyMsg [$Source] [Warning] :: $Msg" }
                        1 { [string]$LegacyTextLogLine = "$LegacyMsg [$Source] [Info] :: $Msg" }
                    }
                } Else {
                    [string]$ConsoleLogLine = "$LegacyMsg :: $Msg"
                    Switch ($Severity) {
                        3 { [string]$LegacyTextLogLine = "$LegacyMsg [Error] :: $Msg" }
                        2 { [string]$LegacyTextLogLine = "$LegacyMsg [Warning] :: $Msg" }
                        1 { [string]$LegacyTextLogLine = "$LegacyMsg [Info] :: $Msg" }
                    }
                }
            }
        
            ## Execute script block to create the CMTrace.exe compatible log entry
            [string]$CMTraceLogLine = & $CMTraceLogString -lMessage $CMTraceMsg -lSource $Source -lSeverity $Severity
        
            ## Choose which log type to write to file
            If ($LogType -ieq 'CMTrace') {
                [string]$LogLine = $CMTraceLogLine
            } Else {
                [string]$LogLine = $LegacyTextLogLine
            }
        
            ## Write the log entry to the log file if logging is not currently disabled
            If (-not $DisableLogging) {
                Try {
                    $LogLine | Out-File -FilePath $LogFilePath -Append -NoClobber -Force -Encoding 'UTF8' -ErrorAction 'Stop'
                } Catch {
                    If (-not $ContinueOnError) {
                        Write-Host -Object "[$LogDate $LogTime] [$ScriptSection] [${CmdletName}] :: Failed to write message [$Msg] to the log file [$LogFilePath]. `n$(Resolve-Error)" -ForegroundColor 'Red'
                    }
                }
            }
        
            ## Execute script block to write the log entry to the console if $WriteHost is $true
            & $WriteLogLineToHost -lTextLogLine $ConsoleLogLine -lSeverity $Severity
        }
    }
    End {
        ## Archive log file if size is greater than $MaxLogFileSizeMB and $MaxLogFileSizeMB > 0
        Try {
            If ((-not $ExitLoggingFunction) -and (-not $DisableLogging)) {
                [IO.FileInfo]$LogFile = Get-ChildItem -LiteralPath $LogFilePath -ErrorAction 'Stop'
                [decimal]$LogFileSizeMB = $LogFile.Length / 1MB
                If (($LogFileSizeMB -gt $MaxLogFileSizeMB) -and ($MaxLogFileSizeMB -gt 0)) {
                    ## Change the file extension to "lo_"
                    [string]$ArchivedOutLogFile = [IO.Path]::ChangeExtension($LogFilePath, 'lo_')
                    [hashtable]$ArchiveLogParams = @{ ScriptSection = $ScriptSection; Source = ${CmdletName}; Severity = 2; LogFileDirectory = $LogFileDirectory; LogFileName = $LogFileName; LogType = $LogType; MaxLogFileSizeMB = 0; WriteHost = $WriteHost; ContinueOnError = $ContinueOnError; PassThru = $false }
        
                    ## Log message about archiving the log file
                    $ArchiveLogMessage = "Maximum log file size [$MaxLogFileSizeMB MB] reached. Rename log file to [$ArchivedOutLogFile]."
                    Write-Log -Message $ArchiveLogMessage @ArchiveLogParams
        
                    ## Archive existing log file from <filename>.log to <filename>.lo_. Overwrites any existing <filename>.lo_ file. This is the same method SCCM uses for log files.
                    Move-Item -LiteralPath $LogFilePath -Destination $ArchivedOutLogFile -Force -ErrorAction 'Stop'
        
                    ## Start new log file and Log message about archiving the old log file
                    $NewLogMessage = "Previous log file was renamed to [$ArchivedOutLogFile] because maximum log file size of [$MaxLogFileSizeMB MB] was reached."
                    Write-Log -Message $NewLogMessage @ArchiveLogParams
                }
            }
        } Catch {
            ## If renaming of file fails, script will continue writing to log file even if size goes over the max file size
        } Finally {
            If ($PassThru) { Write-Output -InputObject $Message }
        }
    }
}

Function Resolve-Error {
    <#
    .SYNOPSIS
        Enumerate error record details.
    .DESCRIPTION
        Enumerate an error record, or a collection of error record, properties. By default, the details for the last error will be enumerated.
    .PARAMETER ErrorRecord
        The error record to resolve. The default error record is the latest one: $global:Error[0]. This parameter will also accept an array of error records.
    .PARAMETER Property
        The list of properties to display from the error record. Use "*" to display all properties.
        Default list of error properties is: Message, FullyQualifiedErrorId, ScriptStackTrace, PositionMessage, InnerException
    .PARAMETER GetErrorRecord
        Get error record details as represented by $_.
    .PARAMETER GetErrorInvocation
        Get error record invocation information as represented by $_.InvocationInfo.
    .PARAMETER GetErrorException
        Get error record exception details as represented by $_.Exception.
    .PARAMETER GetErrorInnerException
        Get error record inner exception details as represented by $_.Exception.InnerException. Will retrieve all inner exceptions if there is more than one.
    .EXAMPLE
        Resolve-Error
    .EXAMPLE
        Resolve-Error -Property *
    .EXAMPLE
        Resolve-Error -Property InnerException
    .EXAMPLE
        Resolve-Error -GetErrorInvocation:$false
    .NOTES
    .LINK
        http://psappdeploytoolkit.com
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [AllowEmptyCollection()]
        [array]$ErrorRecord,
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNullorEmpty()]
        [string[]]$Property = ('Message', 'InnerException', 'FullyQualifiedErrorId', 'ScriptStackTrace', 'PositionMessage'),
        [Parameter(Mandatory = $false, Position = 2)]
        [switch]$GetErrorRecord = $true,
        [Parameter(Mandatory = $false, Position = 3)]
        [switch]$GetErrorInvocation = $true,
        [Parameter(Mandatory = $false, Position = 4)]
        [switch]$GetErrorException = $true,
        [Parameter(Mandatory = $false, Position = 5)]
        [switch]$GetErrorInnerException = $true
    )
    
    Begin {
        ## If function was called without specifying an error record, then choose the latest error that occurred
        If (-not $ErrorRecord) {
            If ($global:Error.Count -eq 0) {
                #Write-Warning -Message "The `$Error collection is empty"
                Return
            } Else {
                [array]$ErrorRecord = $global:Error[0]
            }
        }
    
        ## Allows selecting and filtering the properties on the error object if they exist
        [scriptblock]$SelectProperty = {
            Param (
                [Parameter(Mandatory = $true)]
                [ValidateNotNullorEmpty()]
                $InputObject,
                [Parameter(Mandatory = $true)]
                [ValidateNotNullorEmpty()]
                [string[]]$Property
            )
    
            [string[]]$ObjectProperty = $InputObject | Get-Member -MemberType '*Property' | Select-Object -ExpandProperty 'Name'
            ForEach ($Prop in $Property) {
                If ($Prop -eq '*') {
                    [string[]]$PropertySelection = $ObjectProperty
                    Break
                } ElseIf ($ObjectProperty -contains $Prop) {
                    [string[]]$PropertySelection += $Prop
                }
            }
            Write-Output -InputObject $PropertySelection
        }
    
        #  Initialize variables to avoid error if 'Set-StrictMode' is set
        $LogErrorRecordMsg = $null
        $LogErrorInvocationMsg = $null
        $LogErrorExceptionMsg = $null
        $LogErrorMessageTmp = $null
        $LogInnerMessage = $null
    }
    Process {
        If (-not $ErrorRecord) { Return }
        ForEach ($ErrRecord in $ErrorRecord) {
            ## Capture Error Record
            If ($GetErrorRecord) {
                [string[]]$SelectedProperties = & $SelectProperty -InputObject $ErrRecord -Property $Property
                $LogErrorRecordMsg = $ErrRecord | Select-Object -Property $SelectedProperties
            }
    
            ## Error Invocation Information
            If ($GetErrorInvocation) {
                If ($ErrRecord.InvocationInfo) {
                    [string[]]$SelectedProperties = & $SelectProperty -InputObject $ErrRecord.InvocationInfo -Property $Property
                    $LogErrorInvocationMsg = $ErrRecord.InvocationInfo | Select-Object -Property $SelectedProperties
                }
            }
    
            ## Capture Error Exception
            If ($GetErrorException) {
                If ($ErrRecord.Exception) {
                    [string[]]$SelectedProperties = & $SelectProperty -InputObject $ErrRecord.Exception -Property $Property
                    $LogErrorExceptionMsg = $ErrRecord.Exception | Select-Object -Property $SelectedProperties
                }
            }
    
            ## Display properties in the correct order
            If ($Property -eq '*') {
                #  If all properties were chosen for display, then arrange them in the order the error object displays them by default.
                If ($LogErrorRecordMsg) { [array]$LogErrorMessageTmp += $LogErrorRecordMsg }
                If ($LogErrorInvocationMsg) { [array]$LogErrorMessageTmp += $LogErrorInvocationMsg }
                If ($LogErrorExceptionMsg) { [array]$LogErrorMessageTmp += $LogErrorExceptionMsg }
            } Else {
                #  Display selected properties in our custom order
                If ($LogErrorExceptionMsg) { [array]$LogErrorMessageTmp += $LogErrorExceptionMsg }
                If ($LogErrorRecordMsg) { [array]$LogErrorMessageTmp += $LogErrorRecordMsg }
                If ($LogErrorInvocationMsg) { [array]$LogErrorMessageTmp += $LogErrorInvocationMsg }
            }
    
            If ($LogErrorMessageTmp) {
                $LogErrorMessage = 'Error Record:'
                $LogErrorMessage += "`n-------------"
                $LogErrorMsg = $LogErrorMessageTmp | Format-List | Out-String
                $LogErrorMessage += $LogErrorMsg
            }
    
            ## Capture Error Inner Exception(s)
            If ($GetErrorInnerException) {
                If ($ErrRecord.Exception -and $ErrRecord.Exception.InnerException) {
                    $LogInnerMessage = 'Error Inner Exception(s):'
                    $LogInnerMessage += "`n-------------------------"
    
                    $ErrorInnerException = $ErrRecord.Exception.InnerException
                    $Count = 0
    
                    While ($ErrorInnerException) {
                        [string]$InnerExceptionSeperator = '~' * 40
    
                        [string[]]$SelectedProperties = & $SelectProperty -InputObject $ErrorInnerException -Property $Property
                        $LogErrorInnerExceptionMsg = $ErrorInnerException | Select-Object -Property $SelectedProperties | Format-List | Out-String
    
                        If ($Count -gt 0) { $LogInnerMessage += $InnerExceptionSeperator }
                        $LogInnerMessage += $LogErrorInnerExceptionMsg
    
                        $Count++
                        $ErrorInnerException = $ErrorInnerException.InnerException
                    }
                }
            }
    
            If ($LogErrorMessage) { $Output = $LogErrorMessage }
            If ($LogInnerMessage) { $Output += $LogInnerMessage }
    
            Write-Output -InputObject $Output
    
            If (Test-Path -LiteralPath 'variable:Output') { Clear-Variable -Name 'Output' }
            If (Test-Path -LiteralPath 'variable:LogErrorMessage') { Clear-Variable -Name 'LogErrorMessage' }
            If (Test-Path -LiteralPath 'variable:LogInnerMessage') { Clear-Variable -Name 'LogInnerMessage' }
            If (Test-Path -LiteralPath 'variable:LogErrorMessageTmp') { Clear-Variable -Name 'LogErrorMessageTmp' }
        }
    }
    End {
    }
}


$prevError = ""
Function Trace-Error {
    $errorMsg = Resolve-Error
    if ($errorMsg -and -not $errorMsg -eq $prevError) {
        Write-Log $errorMsg 3
        $prevError = $errorMsg
    }
}

Function Trace-AllErrors {
    $errors = $global:Error
    if($errors){
        Write-Log "Printing errors encountered during script execution." -ScriptSection "Error Printing"
        $errorMsgs = Resolve-Error -ErrorRecord $errors
        Write-Log $errorMsgs 3 -ScriptSection "Error Printing"
    }   
}



