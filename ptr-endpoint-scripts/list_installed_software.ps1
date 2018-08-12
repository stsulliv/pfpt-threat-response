#Print the PowerShell version for context
write-host "PowerShell Version: " $PSVersionTable.PSVersion.tostring()
write-host

#Print a simple list of Installed Programs on localhost  
write-host "========================================================="
write-host "List of Installed Programs on this host."
write-host "========================================================="
write-host

$installList = Get-WmiObject -Class Win32_Product

foreach ($program in $installList) {
    write-host "Name       :" $program.Name
    write-host "Command    :" $program.Version
    write-host "Vendor     :" $program.Vendor
    write-host "Caption    :" $program.Caption
    write-host "Signed     :" $program.Signed
    write-host
}
