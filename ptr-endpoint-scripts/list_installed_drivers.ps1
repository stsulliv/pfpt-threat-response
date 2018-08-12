# Print the PowerShell version for context
write-host "PowerShell Version: " $PSVersionTable.PSVersion.tostring()
write-host

# Print a list of installed 3rd party drivers on localhost. This script requires elevated privileges.

write-host "============================================================="
write-host "List of installed drivers."
write-host "============================================================="
write-host

# Get all drivers
$driverList = driverquery -SI -FO csv | ConvertFrom-Csv | Where-Object { $_.InfName -like "*.inf" }

foreach ($driver in $driverList) {
    write-host "Driver Name       :" $driver.DeviceName
    write-host "File Name         :" $driver.InfName
    write-host "Provider Name     :" $driver.Manufacturer
    write-host "IsSigned          :" $driver.IsSigned
    write-host
}
