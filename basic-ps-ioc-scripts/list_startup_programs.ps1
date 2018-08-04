#Print the PowerShell version for context
write-host "PowerShell Version: " $PSVersionTable.PSVersion.tostring()
write-host

#Print a simple list of Startup Programs on localhost 
$colItems = Get-WmiObject Win32_StartupCommand -computername .

foreach ($objItem in $colItems) {
    write-host "Name       :" $objItem.Name
    write-host "Command    :" $objItem.command
    write-host "Location   :" $objItem.Location
    write-host "User       :" $objItem.User
    write-host
}
