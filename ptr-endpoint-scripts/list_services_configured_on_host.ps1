#Print the PowerShell version for context
write-host "PowerShell Version: " $PSVersionTable.PSVersion.tostring()
write-host

#Print a simple list of Configured Services on localhost

write-host "========================================================="
write-host "List of configured services on this host."
write-host "========================================================="
write-host

$serviceList = Get-Service | Sort-Object -descending Status

foreach ($service in $serviceList) {
    write-host "Service Name            :" $service.ServiceName
    write-host "Display Name            :" $service.DisplayName
    write-host "Service Type            :" $service.ServiceType
    write-host "Start Type              :" $service.StartType
    write-host "Status                  :" $service.Status
    write-host
}
