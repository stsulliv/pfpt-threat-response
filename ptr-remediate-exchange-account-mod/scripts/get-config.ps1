function ptr-Get-Config ($PathRoot) {
    
    if (!([System.IO.File]::Exists("$PathRoot\configuration.xml"))) {
        
        $Exchange_Host = Read-Host 'Please enter the FQDN or IP of your Exchange Server'
    
        $ThreatResponse_Host = Read-Host 'Please enter the FQDN or IP of your Threat Response Server'
        $ThreatResponse_ListId = Read-Host 'Enter the Threat Response user list ID'
       
   
        $AD_ReqChangePw = Read-Host 'Would you like to require users to change password at next logon? (Yes/No)'
        $AD_UpdateCantChange = Read-Host 'Can I update User Cannot Change Password to False? (Yes/No)'
        $AD_UpdatePwdNeverExpires = Read-Host 'Can I update User Password Never Expires to False? (Yes/No)'
        $AD_ResetPw = Read-Host 'Would you like to change the account password? (Yes/No)'
        
        $AD_RemoveMbDelegates = Read-Host 'Would you like to REMOVE Mailbox Delegates? (Yes/No)'
        $AD_DisableExtMailFrwd = Read-Host 'Would you like to DISABLE external forwarding Inbox rules? (Yes/No)'
        $AD_RemoveExtMailFrwd = Read-Host 'Would you like to REMOVE external forwarding Inbox rules? (Yes/No)'
        $AD_DisableMailFrwd = Read-Host 'Would you like to disable Mail forwarding? (Yes/No)'

        $Config =@{ExchangeHost=$Exchange_host;
                    ThreatResponseHost=$PTR_Host;
                    ThreatResponseListId=$PTR_ListId;
                    ReqChangePw=$AD_ReqChangePw;
                    UpdateCantChangePassword=$AD_UpdateCantChange;
                    UpdatePwNeverExpire=$AD_UpdateCantChange;
                    ResetPw=$AD_ResetPw;
                    RemoveMailboxDelegates=$AD_RemoveMbDelegates;
                    DisableExternalMailboxForwardRules=$AD_DisableExtMailFrwd;
                    RemoveExternalMailboxForwardRules=$AD_RemoveExtMailFrwd;
                    DisableMailboxForward=$AD_DisableMailFrwd}
        
        $Config | export-clixml "$PathRoot\configuration.xml"

        return $Config
    }
    else {
        $Config = Import-Clixml "$PathRoot\configuration.xml"

        return $Config
    }
}