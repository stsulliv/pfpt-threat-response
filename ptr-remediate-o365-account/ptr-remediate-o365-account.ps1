# Used link below as reference for Actions against Account
# https://github.com/O365AES/Scripts/wiki/Remediate-Breached-Account

$PathRoot = $PSScriptRoot

function Get-Config ($PathRoot) {
    
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

function Get-PtrKey ($PathRoot) {
    
    if (!([System.IO.File]::Exists("$PathRoot\threatresponse.cred"))) {
    
        $PtrKey = Read-Host -Message "Enter your API Key from Threat Response"
        $PtrKey | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File "$PathRoot\threatresponse.cred" -Force

        return $PtrKey
    }
    else {
        $PtrKeySec = Get-Content "$PathRoot\threatresponse.cred" | ConvertTo-SecureString
        $PtrKey = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((($PtrKeySec))))

        return $PtrKey
    }
}

function Get-Credentials ($PathRoot) {
    
    if (!([System.IO.File]::Exists("$PathRoot\password.cred")) -Or !([System.IO.File]::Exists("$PathRoot\account.cred"))) {
    
        $Credential = Get-Credential -Message "Enter a user name and password"
        $Credential.Password | ConvertFrom-SecureString | Out-File "$PathRoot\password.cred" -Force
        $Credential.UserName | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File "$PathRoot\account.cred" -Force

        return $Credential
    }
    else {
        $PwdSecureString = Get-Content "$PathRoot\password.cred" | ConvertTo-SecureString
        $UsernameSecure = Get-Content "$PathRoot\account.cred" | ConvertTo-SecureString
        $Username = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((($UsernameSecure))))

        $Credential = New-Object System.Management.Automation.PSCredential -ArgumentList $Username, $PwdSecureString

        return $Credential
    }
}

function Get-PTRListMembers ($ptr_key,$ptr_host,$ptr_list) {

    # required to get around Certificate errors
    $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    # build the headers for the jason request
    # PTR requires authorization
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", 'application/json')
    $headers.Add("Authorization", $ptr_key)

    # gets a list of all members of the User List from Threat Response
    $url = "https://$ptr_host/api/lists/$ptr_list/members.json"

    $ListMembers = Invoke-RestMethod -Method Get -Uri $url -Headers $headers

    if ($ListMembers.id.Length -eq 0) {
        '[STOP] There are no members in the PTR User List.  The script will now exit.' | LogStamp
        Exit

    } else {
        'There is(are) ' + $ListMembers.id.Length + ' Member(s) of the the PTR User List ' + $ptr_list | LogStamp
        return $ListMembers
    }
}

function Remove-PTRListMember ($ptr_key, $ptr_host, $ptr_list, $member_id) {
    
    # required to get around Certificate errors
    $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    # build the headers for the jason request
    # PTR requires authorization
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $ptr_key)
    
    $url = "https://${ptr_host}/api/lists/${ptr_list}/members/${member_id}.json"

    'Removing Member number ' + $member_id + ' from PTR list ' + $ptr_list | LogStamp 
    try {
        Invoke-RestMethod -Method Delete -Uri $url -Headers $headers -ContentType 'application/json'
    } catch {
        '[ERROR] Failed to remove Member number ' + $member_id + ' from PTR list ' + $ptr_list | LogStamp
        return
    }

    'Member number ' + $member_id + ' was removed from PTR list ' + $ptr_list | LogStamp
}

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

function Get-AuditLog ($upn, $pathroot) {
    
    'Getting mailbox audit log for ' + $upn + '.' | LogStamp

    # set Log path and create any missing subdirectories
    $PathMbAudit = $pathroot + '\Audit\' + $upn + "-" + (Get-Date).ToString('yyyy-MM-dd-HH-mm') + ".csv"
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

################################# Starting Main Script #################################

# set Log path and create any missing subdirectories
$PathLog = $PathRoot + '\Log\script-' + (Get-Date).ToString('yyyy-MM-dd') + '.log'
$PathLog | % { 
           If (Test-Path -Path $_) { Get-Item $_ } 
           Else { New-Item -ItemType File -Path $_ -Force } 
} 

# filter adds Timestamp and adds content to the Script Log
filter LogStamp {"$(Get-Date -Format O):$_" | Add-Content $PathLog -Force }

'---------- Initializing script Configuration, Key and Credential ----------' | LogStamp

# get script configuration
$Config = Get-Config $PathRoot
'Connecting to PTR host: ' + $Config.Host | LogStamp
'Referencing PTR User List ID : ' + $Config.ListId | LogStamp

# get threat response key
$PtrKey = Get-PtrKey $PathRoot
'Threat Response API Key: ending in ...' + $PtrKey.Substring($PtrKey.Length - 8, 8) | LogStamp

# get Azure credential
$Credential = Get-Credentials $PathRoot
'Using Office 365 account: ' + $Credential.UserName | LogStamp

# get members of threat response list
$ListMembers = Get-PTRListMembers $PtrKey $Config.Host $Config.ListId
'Number of members in PTR List: ' + $ListMembers.id.Length | LogStamp

#Import required Azure AD module
import-module MSOnline

# Connecting to Exchange Online
'Establishing PS-Session with Exchange Online' | LogStamp
$ExoSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri `
    https://outlook.office365.com/powershell-liveid/ `
    -Credential $Credential -Authentication Basic -AllowRedirection

if ($null -ne $ExoSession) {
    'Connected to Exchange Online as ' + $Credential.UserName | LogStamp
    Import-PSSession $ExoSession
} else {
    '[ERROR] Unable to connect to Exchange Online. Verify stored credential, permissions and network.' | LogStamp
    Exit
}

# Connecting to Exchange Online Protection
'Establishing PS-Session with Exchange Online Protection (EOP)' | LogStamp
$EopSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri `
    https://ps.compliance.protection.outlook.com/powershell-liveid/ `
    -Credential $Credential -Authentication Basic -AllowRedirection

if ($null -ne $EopSession) {
    'Connected to Exchange Online Protection as ' + $Credential.UserName | LogStamp
    Import-PSSession $EopSession -AllowClobber

} else {
    '[ERROR] Unable to connect to Exchange Online Protection. Verify stored credential, permissions and network.' | LogStamp
    Exit
}

'Establishing connection with Microsoft Online (MSO)' | LogStamp
try {
    'Connected to Microsoft Online (MSO) as ' + $Credential.UserName | LogStamp
    Connect-MsolService -Credential $Credential

} catch{
    '[ERROR] Unable to connect to Microsoft Online (MSO). Verify stored credential, permissions and network.' | LogStamp
    Exit
}

'Establishing connection with Azure Active Directory (AAD)' | LogStamp
try {
    'Connected to Azure Active Directory as ' + $Credential.UserName | LogStamp
    Connect-AzureAD -Credential $Credential

} catch{
    '[STOP] Unable to connect to Azure Active Directory (AAD). Verify stored credential, permissions and network.' | LogStamp
    Exit
}


#Load "System.Web" assembly in PowerShell console 
[Reflection.Assembly]::LoadWithPartialName("System.Web") 

foreach ($id in $ListMembers) {

    # reverse_user.username for each ID stores the SAMaccount Name
    $samname = $id.reverse_user.username
    "............. Starting Account Remediation of $samname ............." | LogStamp

    # office 365 uses UPN for account name.  Typically the users email address; user@sample.com
    # build the UPN by taking SAMaccount and adding UPN Suffix from Configuration.xml
    $upn = $samname + $Config.UpnSuffix
    
    if ($Config.ReqChangePw -eq 'yes') {
         Require-ChangePassword $upn
    
    } else {
        "[SKIPPED] Requiring password change." | LogStamp 
    }

    if ($Config.ReqStrongPw -eq 'yes') {
        Require-StrongPassword $upn

    } else {
        "[SKIPPED] Requiring strong password." | LogStamp 
    }

    if ($Config.EnableMfa -eq 'yes') {
        Enable-MFA $upn

    } else {
        "[SKIPPED] Enabling multi-factor authentication (MFA)." | LogStamp 
    }

    #
    if ($Config.ResetPw -eq 'yes') {
        Reset-Password $upn

    } else {
        "[SKIPPED] Changing password." | LogStamp 
    }

    if ($Config.EnableMailboxAudit -eq 'yes') {
        Enable-MailboxAuditing $upn

    } else {
        "[SKIPPED] Enabling mailbox auditing." | LogStamp 
    }

    if ($Config.RemoveMailboxDelegates -eq 'yes') {
        Remove-MailboxDelegates $upn

    } else {
        "[SKIPPED] Removing mailbox delegates." | LogStamp 
    }
    
    if ($Config.DisableExternalMailboxForwardRules -eq 'yes' `
        -and $Config.RemoveExternalMailboxForwardRules -ne 'yes' ) {
        
        Disable-MailforwardingRulesToExternalDomains $upn

    } else {
        "[SKIPPED] Disabling external mailbox forwarding rules." | LogStamp
    }

    if ($Config.RemoveExternalMailboxForwardRules -eq 'yes') {
        Disable-MailforwardingRulesToExternalDomains $upn

    } else {
        "[SKIPPED] Removing external mailbox forwarding rules." | LogStamp
    }
    
    if ($Config.DisableMailboxForward -eq 'yes') {
        Disable-MailboxForwarding $upn

    } else {
        "[SKIPPED] Removing mailbox forwarding." | LogStamp 
    }

    if ($Config.RevokeUserLogin -eq 'yes') {
        Revoke-UserLogin $upn

    } else {
        "[SKIPPED] Revoking user logins." | LogStamp 
    }
    
    if ($Config.GetMailboxAudit -eq 'yes') {
        Get-AuditLog $upn $PathRoot

    } else {
        "[SKIPPED] Getting a mailbox audit." | LogStamp 
    }

    Remove-PTRListMember $PtrKey $Config.Host $Config.ListId $id.id

    "............. Finished Account Remediation of $samname ............." | LogStamp
}

# added to cleanup open sessions
'[DISCONNECT] Removing PS-Session with Exchange Online' | LogStamp
Remove-PSSession $ExoSession

'[DISCONNECT] Removing PS_Session with Exchange Online Portection (EOP)' | LogStamp
Remove-PSSession $EopSession

'[DISCONNECT] Exiting connection with Azure Active Directory (AAD)' | LogStamp

Exit
