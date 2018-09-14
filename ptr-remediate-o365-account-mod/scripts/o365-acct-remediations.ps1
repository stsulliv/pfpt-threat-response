function Require-ChangePassword($upn) {
    
    'Forcing ' + $upn + ' to change password at next logon.' | LogStamp
    
    try {  
        Set-MsolUserPassword –UserPrincipalName $upn -ForceChangePassword $True
    
    } catch {  
    
        '[ERROR] Failed to force password change for ' + $upn | LogStamp
        return
    }
    
    $upn + ' will be forced to change password at logon.' | LogStamp
}

function Require-StrongPassword($upn) {
    
    'Requiring ' + $upn + ' to use a strong password.' | LogStamp
    
    try {
    
        Set-MsolUser -UserPrincipalName $upn -StrongPasswordRequired $True
    
    } catch {  
    
        '[ERROR] Failed to require strong password for ' + $upn | LogStamp
        return
    
    }
    
    $upn + ' will be required to use a strong password.' | LogStamp
}

function Enable-MFA ($upn) {
    
    'Enabling multi-factor authentication for ' + $upn + '.' | LogStamp

    #Create the StrongAuthenticationRequirement object and insert required settings
    $mf = New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement
    $mf.RelyingParty = "*"
    $mfa = @($mf)
    
    try {

        Set-MsolUser -UserPrincipalName $upn -StrongAuthenticationRequirements $mfa

    } catch {
        
        '[ERROR] Failed to enable multi-factor authentication (MFA) for ' + $upn | LogStamp
        return
   
    }

    'Multi-factor authentication (MFA) enabled for ' + $upn + '.' | LogStamp
}

function Reset-Password($upn) {
    
    'Changing the account password for ' + $upn + '.' | LogStamp

    # generating random password
    $newPassword = ([System.Web.Security.Membership]::GeneratePassword(16,2))

    try {
    
        Set-MsolUserPassword –UserPrincipalName $upn –NewPassword $newPassword

    } catch {  
    
        '[ERROR] Failed to change the password for ' + $upn | LogStamp
        return
    
    }

    $upn + ' password has been changed to' + $newPassword + '.' | LogStamp
}

function Enable-MailboxAuditing($upn) {
    
    'Enabling mailbox auditing for ' + $upn + '.' | LogStamp

    try {

        Set-Mailbox $upn -AuditEnabled $true -AuditLogAgeLimit 365

    } catch {

        '[ERROR] Failed to enable mailbox auditing for ' + $upn | LogStamp
        return
        
    } 

    'Mailbox auditing enabled for ' + $upn | LogStamp
}

function Remove-MailboxDelegates($upn) {
    
    'Removing mailbox delegates for ' + $upn + '.' | LogStamp

    try {

    $mailboxDelegates = Get-MailboxPermission -Identity $upn | Where-Object {($_.IsInherited -ne "True") -and ($_.User -notlike "*SELF*")}
    
    } catch {
        
        '[ERROR] Failed to get mailbox delegates for ' + $upn | LogStamp
        return

    }

    'Found ' + $mailboxDelegates.Length + ' delegates for ' + $upn | LogStamp

    foreach ($delegate in $mailboxDelegates) {
        
        'Removing ' + $delegate.User + ' from ' + $upn + 'delegates.' | LogStamp
        
        try {

            Remove-MailboxPermission -Identity $upn -User $delegate.User -AccessRights $delegate.AccessRights -InheritanceType All -Confirm:$false

        } catch { 
            
            '[ERROR] Failed to remove delegates ' + $delegates.User + ' from ' + $upn | LogStamp
            return
        }

        'Removed ' + $delegate.User + ' from ' + $upn + 'delegates.' | LogStamp
    }    
}

function Disable-MailforwardingRulesToExternalDomains($upn) {

    'Disable external forward rules for ' + $upn + '.' | LogStamp

    $inboxrules = Get-InboxRule -Mailbox $upn | Where-Object {(($_.Enabled -eq $true) -and `
        (($_.ForwardTo -ne $null) -or ($_.ForwardAsAttachmentTo -ne $null) -or ($_.RedirectTo -ne $null) `
        -or ($_.SendTextMessageNotificationTo -ne $null)))}

    'Found ' + $inboxrules.Length + ' external forward rules for ' + $upn + '.' | LogStamp

    foreach ($rule in $inboxrules) {

        'Disabling ' + $rule.Name + '-' + $rule.RuleIdentity + ' from ' + $upn + '.' | LogStamp

        try {

            Disable-InboxRule -Identity $rule.Identity -Confirm:$false
            # Remove-InboxRule -Identity $rule.Identity -Confirm:$false

        } catch {

            '[ERROR] Failed to disable rule ' + $rule.Name + ' from ' + $upn | LogStamp
            return
        }

        'Disabled ' +$rule.Name + '-' + $rule.RuleIdentity + ' from ' + $upn + '.' | LogStamp
    }

    'Disabled ' + $inboxrules.Length + ' external forward rules for ' + $upn + '.' | LogStamp
}

function Remove-MailforwardingRulesToExternalDomains($upn) {

    'Remove external forward rules for ' + $upn + '.' | LogStamp

    $inboxrules = Get-InboxRule -Mailbox $upn | Where-Object {(($_.Enabled -eq $true) -and `
        (($_.ForwardTo -ne $null) -or ($_.ForwardAsAttachmentTo -ne $null) -or ($_.RedirectTo -ne $null) `
        -or ($_.SendTextMessageNotificationTo -ne $null)))}

    'Found ' + $inboxrules.Length + ' external forward rules for ' + $upn + '.' | LogStamp

    foreach ($rule in $inboxrules) {

        'Removing ' + $rule.Name + '-' + $rule.RuleIdentity + ' from ' + $upn + '.' | LogStamp

        try {

            Remove-InboxRule -Identity $rule.Identity -Confirm:$false

        } catch {

            '[ERROR] Failed to remove rule ' + $rule.Name + ' from ' + $upn | LogStamp
            return
        }

        'Removed ' +$rule.Name + '-' + $rule.RuleIdentity + ' from ' + $upn + '.' | LogStamp
    }

    'Removed ' + $inboxrules.Length + ' external forward rules for ' + $upn + '.' | LogStamp
}

function Disable-MailboxForwarding($upn) {
    
    'Disabling mailbox forward for ' + $upn + '.' | LogStamp

    try {
    
        Set-Mailbox -Identity $upn -DeliverToMailboxAndForward $false -ForwardingSmtpAddress $null

    } catch {
        
        '[ERROR] Failed to disable mailbox forwarding for ' + $upn | LogStamp
        return
    }
    
    'Disabled mailbox forward for ' + $upn + '.' | LogStamp 
}

function Revoke-UserLogin ($upn) {
    
    'Revoking user logins for ' + $upn + '.' | LogStamp

    try {

        Revoke-AzureADUserAllRefreshToken -ObjectId $upn
    
    } catch {
        
        '[ERROR] Failed to revoke user logins for ' + $upn + '.' | LogStamp
        return
    }

    'Revoked user lgoins for ' + $upn + '.' | LogStamp
}

function Get-AuditLog ($upn, $ScriptPath) {
    
    'Getting mailbox audit log for ' + $upn + '.' | LogStamp

    # set Log path and create any missing subdirectories
    $PathMbAudit = $ScriptPath + '\Audit\' + $upn + "-" + (Get-Date).ToString('yyyy-MM-dd-HH-mm') + ".csv"
    $PathMbAudit | % { 
           If (Test-Path -Path $_) { Get-Item $_ } 
           Else { New-Item -ItemType File -Path $_ -Force } 
    } 
    
    $startDate = (Get-Date).AddDays(-30).ToString('MM/dd/yyyy') 
    $endDate = (Get-Date).ToString('MM/dd/yyyy')
    $results = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -UserIds $upn #  
    $results | Export-Csv -Path $PathMbAudit

    'Saved audit log for ' + $upn + '.' | LogStamp   

}
