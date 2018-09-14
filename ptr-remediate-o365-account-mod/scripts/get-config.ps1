function ptr-Get-Config ($PathRoot) {
    
    if (!([System.IO.File]::Exists("$PathRoot\configuration.xml"))) {
    
        $PTR_Host = Read-Host 'Please enter the FQDN or IP of you Threat Response Server'
        $PTR_ListId = Read-Host 'Enter the Threat Response user list ID'
        
        $AD_UpnSuffix = Read-Host 'Enter the UPN suffix (e.g. @example.com)'
   
        $AD_ReqChangePw = Read-Host 'Would you like to require users to change password at next logon? (Yes/No)'
        $AD_ReqStrongPw = Read-Host 'Would you like to require a strong account password? (Yes/No)'
        $AD_EnableMfa = Read-Host 'Would you like to ENABLE Multi-factor Authentication? (Yes/No)'
        $AD_ResetPw = Read-Host 'Would you like to change the account password? (Yes/No)'
        
        $AD_EnableMbAudit = Read-Host 'Would you like to ENABLE Mailbox Auditing? (Yes/No)'
        $AD_RemoveMbDelegates = Read-Host 'Would you like to REMOVE Mailbox Delegates? (Yes/No)'
        $AD_DisableExtMailFrwd = Read-Host 'Would you like to DISABLE external forwarding Inbox rules? (Yes/No)'
        $AD_RemoveExtMailFrwd = Read-Host 'Would you like to REMOVE external forwarding Inbox rules? (Yes/No)'
        $AD_DisableMailFrwd = Read-Host 'Would you like to disable Mail forwarding? (Yes/No)'
        
        $AD_GetAudit = Read-Host 'Would you like to GET the Mailbox Audit log? (Yes/No)'

        $AD_RevokeUserLogin = Read-Host 'Would you like to REVOKE user o365 logins? (Yes/No)'

        $Config =@{Host=$PTR_Host;
                    ListId=$PTR_ListId;
                    UpnSuffix=$AD_UpnSuffix
                    ReqChangePw=$AD_ReqChangePw;
                    ReqStrongPw=$AD_ReqStrongPw;
                    EnableMfa=$AD_EnableMfa;
                    ResetPw=$AD_ResetPw;
                    EnableMailboxAudit=$AD_EnableMbAudit;
                    RemoveMailboxDelegates=$AD_RemoveMbDelegates;
                    DisableExternalMailboxForwardRules=$AD_DisableExtMailFrwd;
                    RemoveExternalMailboxForwardRules=$AD_RemoveExtMailFrwd;
                    DisableMailboxForward=$AD_DisableMailFrwd;
                    GetMailboxAudit=$AD_GetAudit;
                    RevokeUserLogin=$AD_RevokeUserLogin}
        
        $Config | export-clixml "$PathRoot\configuration.xml"

        return $Config
    }
    else {
        $Config = Import-Clixml "$PathRoot\configuration.xml"

        return $Config
    }
}
