#Print the PowerShell version for context
write-host "PowerShell Version: " $PSVersionTable.PSVersion.tostring()
write-host

#Print a simple list of all Scheduled Tasks on localhost  
write-host "========================================================="
write-host "List of Scheduled Tasks on this host."
write-host "========================================================="
write-host

$psMajorVersion = $PSVersionTable.PSVersion.Major

if ($psMajorVersion -ge 3) {
    $taskList = Get-ScheduledTask | sort state -descending

    foreach ($task in $taskList) {
        write-host "Task Name    :" $task.TaskName
        write-host "Task Path    :" $task.TaskPath
        write-host "Author       :" $task.Author
        write-host "Description  :" $task.Description
        write-host "Status        :" $task.State
        write-host
    }
}
else {
    $schedule = new-object -com("Schedule.Service") 
    $schedule.connect() 
    $taskList = $schedule.getfolder("\").gettasks(0)

    foreach ($task in $taskList) {
        write-host "Task Name       :" $task.Name
        write-host "Path            :" $task.Path
        write-host "Last Run Time   :" $task.LastRunTime
        write-host "Next Run Time   :" $task.NextRunTime
        write-host
    }
}
