#Print the PowerShell version for context
write-host "PowerShell Version: " $PSVersionTable.PSVersion.tostring()
write-host

#Print a simple list of all Newest 100 security event logs on localhost  
write-host "========================================================="
write-host "List of Newest 100 Security event logs."
write-host "========================================================="
write-host

# Get all 3rd party drivers
$eventList = get-eventlog -log security -newest 100


foreach ($event in $eventList) {
    write-host "Index       :" $event.Index
    write-host "Time        :" $event.TimeGenerated
    write-host "EntryType   :" $event.EntryType
    write-host "Source      :" $event.Source
    write-host "Event ID    :" $event.EventID
    write-host "Message     :" $event.Message
    write-host
    Write-host "************************************************************************"
    write-host
    }
