<#
.SYNOPSIS
    Export of Windows Event Logs to single CSV file.
.DESCRIPTION     
    Powershell program which exports single specified or all Event Logs (called "channels" in official Microsoft documentation) to 
    one CSV file ina way what <EventData> event record structure is split to multiple CSV columns. 
.PARAMETER 
    paramPathToSaveFiles - path to create log file, if not specified will take current script execution path.
    paramAllLogsOrSingleLog - name of an Event Log channel to process ("security", "application" for example), or "all" - in this case it will process all chanells registered
    in the system to a single CSV file. Each channel will have diferent ContainerLog column value (actually a channel name)
    paramNrOfLogRecordsToProcess - max records to process for each channel. Upon reaching this number of events it will switch to another channel. Put low value here for 
    testing the script
.OUTPUTS
    Program utilize LogWrite function which program messages to both screen and log file. Also adds script contents to log file :)
    Two files are created in the same folder where run program is located:
    <yyyyMMdd-HHmmss>_<hostname>_eventlog_scope<channel_name|all>.csv" - containing actual data exported to CSV file
    <yyyyMMdd-HHmmss>_<hostname>_eventlog_scope<channel_name|all>.log" - all messages the program prints to screen. At the end contains OS and Powershell versions
    and currently run script contents.

.NOTES
    Run in elevated powershell (RunaAs administrator). Reading channels like "Security" requires this.
    For all exported elements of event log it will replace " to ' to avoid confusion with CSV structure.
    Program gives me processing speed ~25 records per second if run on Powershell 5.2, and ~600 records per second if run on Powershell.7.x
    At the end of a program there is an example code which reads just created CSV and filters it by extracting interactive logons and LDAP connections
    Program is created as Proof Of Concept and provided as is, with absolutely no warranty expressed or implied. Any use is at your own risk.
    Author: Aleksandr Reznik (aleksandr@reznik.lt)
#>

param (
    [string]$paramPathToSaveFiles=$PSScriptRoot +"\", #by default equals to currently run script directory   
    [string]$paramAllLogsOrSingleLog = "all", # "all" - all possible logs will be processed, "single log name" - only this log will be processed. "Security" for example
    $paramNrOfLogRecordsToProcess = 50000000
)
$global:pathToLogFile = ""

Function LogWrite{
    #prints output to both screen and file, adds currently executed file contents to log
    [CmdletBinding()]
    Param (
    [string]$paramTextToWrite,
    [string]$paramPathToLogFile = "",
    [Parameter(Mandatory=$False)]
    [string]$ForegroundColor = "gray",
    [switch]$NoNewLine,
    [switch]$AddScriptContentsToLogFile #- will add PS and OS versions and content of current file to logfile, this paramater should be used at the end of execution of your program
    )

    if ($paramPathToLogFile -eq ""){#if path to log is not specified in function call parameters - take value from global variable (to avoid writing to many parameters in function call)
        $paramPathToLogFile = $global:pathToLogFile
    }
    if (!$AddScriptContentsToLogFile)
    {    
        $timeStampStr = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
        $str4file = $timeStampStr + " "+ $paramTextToWrite
        
        #adding to file
        Add-content $paramPathToLogFile -value $str4file    
        
        #printing to screen
        if ($NoNewLine){   
            write-host $paramTextToWrite -ForegroundColor $ForegroundColor -NoNewLine
            }
        else{
            write-host $paramTextToWrite -ForegroundColor $ForegroundColor 
        }
    }
    else { # parameter AddScriptContentsToLogFile is specified  - adding PS version, OS version and content of current file to log
        
        #adding Powershell Version
        #$psVersionStr =  $psversiontable.GetEnumerator().ForEach({ "$($_.Name)=$($_.Value)`r`n" }) 
        $psVersionStr ="End of program execution`r`n`r`n`####################################`r`nPowershell version:`r`n$($psversiontable.GetEnumerator().ForEach({ "$($_.Name)=$($_.Value)`r`n" }))"
        Add-content $paramPathToLogFile -value "End of execution`r`n`####################################r`nPowershell version:`r`n$($psVersionStr)"
        write-host $psVersionStr
        
        #adding OS Version
        $osSTR ="`r`n####################################`r`nOS version:`r`n$([Environment]::OSVersion)"   
        Add-content $paramPathToLogFile -value $osStr
        write-host $osSTR
        write-host
        
        #adding current script 
        $currentPS1file = $PSCommandPath
        $sourceCode = Get-Content $currentPS1file -Raw 
        Add-content $paramPathToLogFile -value "`r`n####################################`r`nFILE BEING EXECUTED:`r`n"
        Add-content $paramPathToLogFile -value $sourceCode
        write-output "Log of operations together with sourcecode of current file is written to $paramPathToLogFile"

    }
}#end of logWrite function

 

######################################################################################################
########################################    PROGRAM BEGIN     ########################################
######################################################################################################
$hostname = $env:computername


$CurrDateTimeStr=[DateTime]::Now.ToString("yyyyMMdd-HHmmss")
$fileNamePrefix = "$($CurrDateTimeStr)_$($hostname)_eventLog_scope_$((Get-Culture).TextInfo.ToTitleCase( $paramAllLogsOrSingleLog.ToLower()))"
$pathToCsvFile = "$($paramPathToSaveFiles)$($fileNamePrefix).csv"
$global:pathToLogFile = "$($paramPathToSaveFiles)$($fileNamePrefix).log"



$computerTogetLogsFrom = "localhost"
#$operationStartTime = Get-Date
$logNames = Get-WinEvent -ComputerName $computerTogetLogsFrom  -ListLog * | Where-Object {$_.RecordCount -ne 0 -and $_.RecordCount}

#scan all logs registered on a system or only single eventlog
if($paramAllLogsOrSingleLog.ToLower() -ne "all") {
    $logNames = $logNames.where{$_.logname -eq $paramAllLogsOrSingleLog.ToLower()}
}

#writing header to file
$currStr =  "`"DateTime`",`"ContainerLog`",`"RecordID`",`"EventID`",`"LevelDisplayName`",`"keyWordDisplayNames`",`"ProviderName`",`"TaskDisplayName`",`"Message`""
    for($i=0;$i -lt $numberOfProperties;$i++){
        $currStr = $currStr + ",`"P"+$i.ToString().ToUpper() + "`""
    }
    $currStr = $currStr + "`r`n"

foreach($logname in $logNames){
    
    
    LogWrite ""
    LogWrite "Logname:$($logname.Logname)"
    $numberOfRecords = (Get-WinEvent -ListLog $logname.Logname).RecordCount
    $operationStartTime = Get-Date
    LogWrite "Start fetching records for log $($logname.Logname) with Get-WinEvent. Record limitation $paramNrOfLogRecordsToProcess"
    $filteredEventList = Get-WinEvent -FilterHashtable @{logname = $logname.logname}  -ErrorAction Continue| Select-Object -First $paramNrOfLogRecordsToProcess
    #$filteredEventList = Get-WinEvent -ComputerName $computerTogetLogsFrom -FilterHashtable @{logname = $logname.logname}  -ErrorAction Continue| Select-Object -First $paramNrOfLogRecordsToProcess
    $oldestEvent = Get-WinEvent -ComputerName $computerTogetLogsFrom -logname $logname.logname -oldest -MaxEvents 1
    $newestEvent = Get-WinEvent -ComputerName $computerTogetLogsFrom -logname $logname.logname -maxEvents 1
    $numberOfFilteredRecords = $filteredEventList.count
    LogWrite "Finish fetching records. Total number of records in log: $numberOfRecords. Number of filtered records: $numberOfFilteredRecords"
    LogWrite "Elapsed time: $((Get-Date) - $operationStartTime)"
    #$filteredEventList = Get-WinEvent -ComputerName $computerTogetLogsFrom -FilterHashtable @{logname = "Application"}  -ErrorAction Continue| Select-Object -First $paramNrOfLogRecordsToProcess
    
    $numberOfProperties = 27
    $maxProperties = 0
    $eventNr = 0
    $strBlockSize = 1000
    $currBlockLine = 1
    $strBlock = ""

    LogWrite ""
    LogWrite "Start saving fetched records to normalized CSV file"
    
    $operationStartTime = Get-Date
    
    $strBlock  = $strBlock + $currStr
    $blockStartTime = Get-Date
    foreach($currEvent in $filteredEventList){
        $eventNr++
        $eventDateTime = $currEvent.TimeCreated.ToString()
        $eventID = $currEvent.Id.ToString()
        $numOfProperties = $currEvent.Properties.Count
        if ($numOfproperties -gt $maxProperties){$maxProperties = $numOfproperties}
        
        try{
            if($currEvent.ContainerLog) {$containerLog = $currEvent.ContainerLog}
                else {$containerLog = "empty"}
            if ($currEvent.RecordId) {$recID = $currEvent.RecordId}
                else {$recID = "empty"}
            if ($currEvent.LevelDisplayName) {$lvlDispName = $currEvent.LevelDisplayName}
                else {$lvlDispName = "empty"}
            if ($currEvent.KeywordsDisplayNames) {$keywordsDispName = $currEvent.KeywordsDisplayNames[0]}
                else {$keywordsDispName  = "empty"}
            if ($currEvent.ProviderName) {$providerName = $currEvent.ProviderName}    
                else {$providerName = "empty"}
            if ($currevent.TaskDisplayName) {$taskDispName = $currevent.TaskDisplayName}
                else {$taskDispName = "empty"}
            if ($currEvent.Message) {$message = $currEvent.Message.replace("`"","`'")}
                else {$message = "empty"}
            
            $currStr =  "`"" + $eventDateTime + "`",`"" + $containerLog +  "`",`"" + $recID +  "`",`"" + $eventID + "`",`""  + $lvlDispName + "`",`"" + $keywordsDispName + "`",`"" + $providerName + "`",`"" + $taskDispName + "`",`"" + $message  + "`""
            for($i=0; $i -lt $numberOfProperties; $i++ ){
                if($i -lt $numOfProperties){
                    $currStr = $currStr + ",`"" + ($currEvent.Properties[$i].value.toString()).replace("`"","`'") + "`""
                    
                }
                else{
                    $currStr = $currStr + ",`"`""
                }
            }
            $currStr = $currStr + "`r`n"

            $strBlock  = $strBlock + $currStr
            $currBlockLine++
            
            if(($eventNr % $strBlockSize) -eq 0 -or ($eventNr -eq $numberOfFilteredRecords)){
                Add-Content $pathToCsvFile $strBlock
                $blockFinishTime = Get-Date
                $timeDelta = $blockFinishTime - $blockStartTime
                if ($timeDelta.TotalSeconds -ne 0){
                    $recordsPerSecond = [int][Math]::Round($strBlockSize/$timeDelta.TotalSeconds)
                }
                else{
                    $recordsPerSecond = 0
                }
                LogWrite "New block added to file. Current EventNr is $($eventNr) from $numberOfFilteredRecords. Block processing speed $recordsPerSecond records per second"
                $blockStartTime = Get-Date
                $strBlock = ""
            }

        } #try
        catch{
            $errorMsg = $Error[0].Exception.Message
            LogWrite "Error caught! $errorMsg"
        }
    }# foreach currEvent
    LogWrite "Finish writing records to CSV. Number of records added: $numberOfFilteredRecords"
    $operationEndTime = Get-Date
    $operationDuration = $operationEndTime - $operationStartTime
    LogWrite "Elapsed time: $($operationDuration)"
    if ($operationDuration.TotalSeconds -ne 0){
        $recordsPerSecond = [int][Math]::Round($numberOfFilteredRecords/$operationDuration.TotalSeconds)
    }
    else{
        $recordsPerSecond = 0
    }
    LogWrite "Speed $($recordsPerSecond) records per second"
    LogWrite "Number of filtered records in processed Event log $($numberOfFilteredRecords)"
    LogWrite "Newest event from fitered records: $($newestEvent.TimeCreated.ToString())"
    LogWrite "Oldest event from fitered records: $($oldestEvent.TimeCreated.ToString())"
    LogWrite "Record to process limit(filter): $($paramNrOfLogRecordsToProcess)"
    if($numberOfRecords -gt $paramNrOfLogRecordsToProcess){
        LogWrite "Warning! Not all records are processed as you have paramNrOfLogRecordsToProcess variable equal to $paramNrOfLogRecordsToProcess, while log has $numberOfRecords records. Increase paramNrOfLogRecordsToProcess variable value." -ForegroundColor red 
    }

}# foreach log
LogWrite


LogWrite "Normalized eventlog information is written to $pathToCsvFile file"
LogWrite -AddScriptContentsToLogFile
$operationStartTime = Get-Date

LogWrite
LogWrite "Testing importing and filtering of just created CSV file"
LogWrite "Start Import-CSV"
$PSOobj4CSV = import-CSV  -path $pathToCsvFile
LogWrite "End Import-CSV"
LogWrite "Elapsed time: $((Get-Date) - $operationStartTime)"
LogWrite

$pathToIntLogonsCSV = "$($paramPathToSaveFiles)$($CurrDateTimeStr)_$($hostname)_interactiveLogons.csv"
$PSOobj4CSV|Where-Object{$_.ContainerLog -eq "Security" -and $_.eventID -eq "4648" -and $_.p12 -ne "-"}|
select  `
@{N='DateTime'; E={$_.DateTime}},
@{N='EventID'; E={$_.EventID}},
@{N='ContainerLog'; E={$_.ContainerLog}},
@{N='LevelDisplayName'; E={$_.LevelDisplayName}},
@{N='keyWordDisplayNames'; E={$_.keyWordDisplayNames}},
@{N='TaskDisplayName'; E={$_.TaskDisplayName}},
@{N='Message'; E={$_.Message}},
@{N='AccountName'; E={$_.P5}},
@{N='SID'; E={$_.P0}},
@{N='IpAddress'; E={$_.P12}}|export-CSV  $pathToIntLogonsCSV -NoTypeInformation -append  -force
LogWrite "Interactive logons written to $pathToIntLogonsCSV file"

$pathToLdapLogonsCSV = "$($paramPathToSaveFiles)$($CurrDateTimeStr)_$($hostname)_LDAPlogons.csv"
$PSOobj4CSV|Where-Object{$_.ContainerLog -eq "Security" -and $_.eventID -eq "4624" -and $_.EventID -eq "4625" -and $_.p4.length -gt 10}|
select  `
@{N='DateTime'; E={$_.DateTime}},
@{N='EventID'; E={$_.EventID}},
@{N='ContainerLog'; E={$_.ContainerLog}},
@{N='LevelDisplayName'; E={$_.LevelDisplayName}},
@{N='keyWordDisplayNames'; E={$_.keyWordDisplayNames}},
@{N='TaskDisplayName'; E={$_.TaskDisplayName}},
@{N='Message'; E={$_.Message}},
@{N='AccountName'; E={$_.P5}},
@{N='IPAddress'; E={$_.P18}}|export-CSV  $pathToIntLogonsCSV -NoTypeInformation -append  -force
LogWrite "LDAP logons written to $pathToLdapLogonsCSV file"
#>
