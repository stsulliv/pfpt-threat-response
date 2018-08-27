function Require-ChangePassword($current_user,$UpdateUserCantChangePassword,$UpdatePwNeverExpire) {

    $samname = $current_user.UserPrincipalName
    
# check is ChangePasswordNextLogon is aleady true
    if ($current_user.ChangePasswordAtLogon -eq 'True') {

        "$samname AD property ChangePasswordAtLogon is already TRUE" | LogStamp

        return
    }

    # In order to set "ChangePasswordNextLogon" to $TRUE, user's cannot be prevented form changing password
    if ($current_user.CannotChangePassword -eq 'True') {

        # if $ad_update is set to TRUE, the user property ChangePasswordNextLogon will be set to $false.
        if ($UpdateUserCantChangePassword -eq 'yes') {

            Set-ADUser -Identity $current_user.SamAccountName -CannotChangePassword:$false

            "$samname AD property UserCannotChangePassword UPDATED to FALSE" | LogStamp
        } else {

            "[ERROR] $samname AD property UserCannotChangePassword is TRUE" | LogStamp

            return
        }
    }

    # In order to set "ChangePasswordNextLogon" to $TRUE, user's password cannot be set to Never Expires
    if ($current_user.PasswordNeverExpires -eq 'True') {

        if ($UpdatePwNeverExpire -eq 'yes') {

            Set-ADUser -Identity $current_user.SamAccountName -PasswordNeverExpires:$false

            "$samname AD property PasswordNeverExpires UPDATED to FALSE" | LogStamp
        } else {

            "[ERROR] $samname AD property PasswordNeverExpires is TRUE" | LogStamp

            return
        }
    }

    try {
            
        Set-ADUser -Identity $current_user.SamAccountName -ChangePasswordAtLogon:$true

        "$samname AD property ChangePasswordAtLogon UPDATED to $TRUE" | LogStamp
    } catch {

        "[ERROR] $samname set AD property ChangePasswordAtLogon failed" | LogStamp
    }
}

function Reset-Password($samname) {
    
    'Changing the account password for ' + $samname + '.' | LogStamp

    # generating random password
    $randomstring = ([System.Web.Security.Membership]::GeneratePassword(16,2))
    $newpwd = ConvertTo-SecureString -String $randomstring -AsPlainText –Force

    try {
    
        Set-ADAccountPassword $samname –NewPassword $newpwd -Reset

    } catch {  
    
        '[ERROR] Failed to change the password for ' + $samname | LogStamp
        return
    
    }

    $samname + ' password has been changed to: ' + $randomstring + '.' | LogStamp
}

function Remove-MailboxDelegates($samname) {
    
    'Removing mailbox delegates for ' + $samname + '.' | LogStamp

    try {

    $mailboxDelegates = Get-MailboxPermission -Identity $samname | Where-Object {($_.IsInherited -ne "True") -and ($_.User -notlike "*SELF*")}
    
    } catch {
        
        '[ERROR] Failed to get mailbox delegates for ' + $samname | LogStamp
        return

    }

    'Found ' + $mailboxDelegates.Length + ' delegates for ' + $samname | LogStamp

    foreach ($delegate in $mailboxDelegates) {
        
        'Removing ' + $delegate.User + ' from ' + $samname + ' delegates.' | LogStamp
        
        try {

            Remove-MailboxPermission -Identity $samname -User $delegate.User -AccessRights $delegate.AccessRights -InheritanceType All -Confirm:$false

        } catch { 
            
            '[ERROR] Failed to remove delegates ' + $delegates.User + ' from ' + $samname | LogStamp
            return
        }

        'Removed ' + $delegate.User + ' from ' + $samname + 'delegates.' | LogStamp
    }    
}

function Disable-MailforwardingRulesToExternalDomains($samname) {

    'Disable external forward rules for ' + $samname + '.' | LogStamp

    $inboxrules = Get-InboxRule -Mailbox $samname | Where-Object {(($_.Enabled -eq $true) -and `
        (($_.ForwardTo -ne $null) -or ($_.ForwardAsAttachmentTo -ne $null) -or ($_.RedirectTo -ne $null) `
        -or ($_.SendTextMessageNotificationTo -ne $null)))}

    'Found ' + $inboxrules.Length + ' external forward rules for ' + $samname + '.' | LogStamp

    foreach ($rule in $inboxrules) {

        'Disabling ' + $rule.Name + '-' + $rule.RuleIdentity + ' from ' + $samname + '.' | LogStamp

        try {

            Disable-InboxRule -Identity $rule.Identity -Confirm:$false
            # Remove-InboxRule -Identity $rule.Identity -Confirm:$false

        } catch {

            '[ERROR] Failed to disable rule ' + $rule.Name + ' from ' + $samname | LogStamp
            return
        }

        'Disabled ' +$rule.Name + '-' + $rule.RuleIdentity + ' from ' + $samname + '.' | LogStamp
    }

    'Disabled ' + $inboxrules.Length + ' external forward rules for ' + $samname + '.' | LogStamp
}

function Remove-MailforwardingRulesToExternalDomains($samname) {

    'Remove external forward rules for ' + $samname + '.' | LogStamp

    $inboxrules = Get-InboxRule -Mailbox $samname | Where-Object {(($_.Enabled -eq $true) -and `
        (($_.ForwardTo -ne $null) -or ($_.ForwardAsAttachmentTo -ne $null) -or ($_.RedirectTo -ne $null) `
        -or ($_.SendTextMessageNotificationTo -ne $null)))}

    'Found ' + $inboxrules.Length + ' external forward rules for ' + $samname + '.' | LogStamp

    foreach ($rule in $inboxrules) {

        'Removing ' + $rule.Name + '-' + $rule.RuleIdentity + ' from ' + $samname + '.' | LogStamp

        try {

            Remove-InboxRule -Identity $rule.Identity -Confirm:$false

        } catch {

            '[ERROR] Failed to remove rule ' + $rule.Name + ' from ' + $samname | LogStamp
            return
        }

        'Removed ' +$rule.Name + '-' + $rule.RuleIdentity + ' from ' + $samname + '.' | LogStamp
    }

    'Removed ' + $inboxrules.Length + ' external forward rules for ' + $samname + '.' | LogStamp
}

function Disable-MailboxForwarding($samname) {
    
    'Disabling mailbox forward for ' + $samname + '.' | LogStamp

    try {
    
        Set-Mailbox -Identity $samname -DeliverToMailboxAndForward $false -ForwardingAddress $null -Force

    } catch {
        
        '[ERROR] Failed to disable mailbox forwarding for ' + $samname | LogStamp
        return
    }
    
    'Disabled mailbox forward for ' + $samname + '.' | LogStamp 
}