function ptr-Get-Config ($PathRoot) {
    
    if (!([System.IO.File]::Exists("$PathRoot\configuration.xml"))) {
    
        $PTR_Host = Read-Host 'Please enter the FQDN or IP of your Threat Response Server'
        $PTR_ListId = Read-Host 'Enter the Threat Response user list ID'

        $SEP_Host = Read-Host 'Please enter the FQDN or IP of your SEP Server'
        $SEP_ListId = Read-Host 'Enter the SEP Quarantine list ID'
        $SEP_Admin = Read-Host 'Enter SEP Admin Username'

        $Config =@{PTR_Host=$PTR_Host;
                    PTR_ListId=$PTR_ListId;
                    SEP_Host=$SEP_Host;
                    SEP_ListId=$SEP_ListId;
                    SEP_Admin=$SEP_Admin}
        
        $Config | export-clixml "$PathRoot\configuration.xml"

        return $Config
    }
    else {
        $Config = Import-Clixml "$PathRoot\configuration.xml"

        return $Config
    }
}