# Used link below as reference for Actions against Account
# https://github.com/O365AES/Scripts/wiki/Remediate-Breached-Account

$PathRoot = $PSScriptRoot

# function stores or loads script variables
# see https://ugliscripts.com/storing-script-variables for details on Get-Variables
function Get-Variables ($PathRoot) {
    
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
                    GetMailboxAudit=$AD_GetAudit}
        
        $Config | export-clixml "$PathRoot\configuration.xml"

        return $Config
    }
    else {
        $Config = Import-Clixml "$PathRoot\configuration.xml"

        return $Config
    }
}

# function stores or loads a string securely
# see https://ugliscripts.com/storing-secure-strings for details on Get-Secret
function Get-Secret ($PathRoot) {
    
    if (!([System.IO.File]::Exists("$PathRoot\threatresponse.cred"))) {
    
        $PtrKey = Read-Host -Message "Enter your API Key from Threat Response"
        $PtrKey | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File "$PathRoot\threatresponse.cred" -Force

        return $PtrKey
    }
    else {
        $PtrKeySec = Get-Content "$PathRoot\threatresponse.cred" | ConvertTo-SecureString -AsPlainText -Force
        $PtrKey = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((($PtrKeySec))))

        return $PtrKey
    }
}

# function stores or loads user credentials
# see https://github.com/stsulliv/powershell/tree/master/storing-user-credentials for details on Get-Cedentials
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
        '[RETURN] There is(are) ' + $ListMembers.id.Length + ' Member(s) of the the PTR User List ID: ' + $ptr_list | LogStamp
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

    '[UPDATE LIST] Removing Member number ' + $member_id + ' from PTR list ' + $ptr_list | LogStamp 
    try {
        Invoke-RestMethod -Method Delete -Uri $url -Headers $headers -ContentType 'application/json'
    } catch {
        '[STOP] Failed to remove Member number ' + $member_id + ' from PTR list ' + $ptr_list | LogStamp
        return
    }

    '[SUCCESS] Member number ' + $member_id + ' was removed from PTR list ' + $ptr_list | LogStamp
}

function Require-ChangePassword($upn) {
    
    '[REMEDIATE] Forcing ' + $upn + ' to change password at next logon.' | AuditStamp
    
    try {  
        Set-MsolUserPassword –UserPrincipalName $upn -ForceChangePassword $True
    
    } catch {  
    
        '[STOP] Failed to force password change for ' + $upn | AuditStamp
        return
    }
    
    '[SUCCESS] ' + $upn + ' will be forced to change password at logon.' | AuditStamp
}

function Require-StrongPassword($upn) {
    
    '[REMEDIATE] Requiring ' + $upn + ' to use a strong password.' | AuditStamp
    
    try {
    
        Set-MsolUser -UserPrincipalName $upn -StrongPasswordRequired $True
    
    } catch {  
    
        '[STOP] Failed to require strong password for ' + $upn | AuditStamp
        return
    
    }
    
    '[SUCCESS] ' + $upn + ' will be required to use a strong password.' | AuditStamp
}

function Enable-MFA ($upn) {
    
    '[REMEDIATE] Enabling multi-factor authentication for ' + $upn + '.' | AuditStamp

    #Create the StrongAuthenticationRequirement object and insert required settings
    $mf = New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement
    $mf.RelyingParty = "*"
    $mfa = @($mf)
    
    try {

        Set-MsolUser -UserPrincipalName $upn -StrongAuthenticationRequirements $mfa

    } catch {
        
        '[STOP] Failed to enable multi-factor authentication (MFA) for ' + $upn | AuditStamp
        return
   
    }

    '[SUCCESS] Multi-factor authentication (MFA) enabled for ' + $upn + '.' | AuditStamp
}

function Reset-Password($upn) {
    
    '[REMEDIATE] Changing the account password for ' + $upn + '.' | AuditStamp
    
    # generating random password
    $newPassword = ([System.Web.Security.Membership]::GeneratePassword(16,2))

    try {
    
        Set-MsolUserPassword –UserPrincipalName $upn –NewPassword $newPassword

    } catch {  
    
        '[STOP] Failed to change the password for ' + $upn | AuditStamp
        return
    
    }

    '[SUCCESS] ' + $upn + ' password has been changed to' + $newPassword + '.' | AuditStamp
}

function Enable-MailboxAuditing($upn) {
    
    '[REMEDIATE] Enabling mailbox auditing for ' + $upn + '.' | AuditStamp

    try {

        Set-Mailbox $upn -AuditEnabled $true -AuditLogAgeLimit 365

    } catch {

        '[STOP] Failed to enable mailbox auditing for ' + $upn | AuditStamp
        return
        
    } 

    '[SUCCESS] Mailbox auditing enabled for ' + $upn | AuditStamp
}

function Remove-MailboxDelegates($upn) {
    
    '[REMEDIATE] Removing mailbox delegates for ' + $upn + '.' | AuditStamp

    try {

    $mailboxDelegates = Get-MailboxPermission -Identity $upn | Where-Object {($_.IsInherited -ne "True") -and ($_.User -notlike "*SELF*")}
    
    } catch {
        
        '[STOP] Failed to get mailbox delegates for ' + $upn | AuditStamp
        return

    }

    '[RESPONSE] Found ' + $mailboxDelegates.Length + ' delegates for ' + $upn | AuditStamp

    foreach ($delegate in $mailboxDelegates) {
        
        '[REMEDIATE] Removing ' + $delegate.User + ' from ' + $upn + 'delegates.' | AuditStamp
        
        try {

            Remove-MailboxPermission -Identity $upn -User $delegate.User -AccessRights $delegate.AccessRights -InheritanceType All -Confirm:$false

        } catch { 
            
            '[STOP] Failed to remove delegates ' + $delegates.User + ' from ' + $upn | AuditStamp
            return
        }

        '[SUCCESS] Removed ' + $delegate.User + ' from ' + $upn + 'delegates.' | AuditStamp
    }    
}

function Disable-MailforwardingRulesToExternalDomains($upn) {

    '[REMEDIATE] Disable external forward rules for ' + $upn + '.' | AuditStamp

    $inboxrules = Get-InboxRule -Mailbox $upn | Where-Object {(($_.Enabled -eq $true) -and `
        (($_.ForwardTo -ne $null) -or ($_.ForwardAsAttachmentTo -ne $null) -or ($_.RedirectTo -ne $null) `
        -or ($_.SendTextMessageNotificationTo -ne $null)))}

    '[RESPONSE] Found ' + $inboxrules.Length + ' external forward rules for ' + $upn + '.' | AuditStamp

    foreach ($rule in $inboxrules) {

        '[REMEDIATE] Disabling ' + $rule.Name + '-' + $rule.RuleIdentity + ' from ' + $upn + '.' | AuditStamp

        try {

            Disable-InboxRule -Identity $rule.Identity -Confirm:$false
            # Remove-InboxRule -Identity $rule.Identity -Confirm:$false

        } catch {

            '[STOP] Failed to disable rule ' + $rule.Name + ' from ' + $upn | AuditStamp
            return
        }

        '[SUCCESS] Disabled ' +$rule.Name + '-' + $rule.RuleIdentity + ' from ' + $upn + '.' | AuditStamp
    }

    '[SUCCESS] Disabled ' + $inboxrules.Length + ' external forward rules for ' + $upn + '.' | AuditStamp
}

function Remove-MailforwardingRulesToExternalDomains($upn) {

    '[REMEDIATE] Remove external forward rules for ' + $upn + '.' | AuditStamp

    $inboxrules = Get-InboxRule -Mailbox $upn | Where-Object {(($_.Enabled -eq $true) -and `
        (($_.ForwardTo -ne $null) -or ($_.ForwardAsAttachmentTo -ne $null) -or ($_.RedirectTo -ne $null) `
        -or ($_.SendTextMessageNotificationTo -ne $null)))}

    '[RESPONSE] Found ' + $inboxrules.Length + ' external forward rules for ' + $upn + '.' | AuditStamp

    foreach ($rule in $inboxrules) {

        '[REMEDIATE] Removing ' + $rule.Name + '-' + $rule.RuleIdentity + ' from ' + $upn + '.' | AuditStamp

        try {

            Remove-InboxRule -Identity $rule.Identity -Confirm:$false

        } catch {

            '[STOP] Failed to remove rule ' + $rule.Name + ' from ' + $upn | AuditStamp
            return
        }

        '[SUCCESS] Removed ' +$rule.Name + '-' + $rule.RuleIdentity + ' from ' + $upn + '.' | AuditStamp
    }

    '[SUCCESS] Removed ' + $inboxrules.Length + ' external forward rules for ' + $upn + '.' | AuditStamp
}

function Disable-MailboxForwarding($upn) {
    
    '[REMEDIATE] Disabling mailbox forward for ' + $upn + '.' | AuditStamp

    try {
    
        Set-Mailbox -Identity $upn -DeliverToMailboxAndForward $false -ForwardingSmtpAddress $null

    } catch {
        
        '[STOP] Failed to disable mailbox forwarding for ' + $upn | AuditStamp
        return
    }
    
    '[SUCCESS] Disabled mailbox forward for ' + $upn + '.' | AuditStamp 
}

function Get-AuditLog ($upn, $pathroot) {
    
    '[AUDIT] Getting mailbox audit log for ' + $upn + '.' | AuditStamp

    # set Log path and create any missing subdirectories
    $PathMbAudit = $pathroot + '\Audit\' + $upn + "\AuditLog" + (Get-Date).ToString('yyyy-MM-dd-HH-mm') + ".csv"
    $PathMbAudit | % { 
           If (Test-Path -Path $_) { Get-Item $_ } 
           Else { New-Item -ItemType File -Path $_ -Force } 
    } 
    
    $startDate = (Get-Date).AddDays(-7).ToString('MM/dd/yyyy') 
    $endDate = (Get-Date).ToString('MM/dd/yyyy')
    $results = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -UserIds $upn
    $results | Export-Csv -Path $PathAudit

    '[SUCCESS] Saved audit log for ' + $upn + ' to path ' + $PathMbAudit + '.' | AuditStamp   

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

$Config = Get-Variables $PathRoot
'[CONFIGURATION] Connecting to PTR host: ' + $Config.Host | LogStamp
'[CONFIGURATION] Referencing PTR User List ID : ' + $Config.ListId | LogStamp

$PtrKey = Get-Secret $PathRoot
'[CREDENTIAL] Threat Response API Key: ' + $PtrKey | LogStamp

$ListMembers = Get-PTRListMembers $PtrKey $Config.Host $Config.ListId
'[USER QUEUE] Number of members in PTR List: ' + $ListMembers.id.Length | LogStamp

$Credential = Get-Credentials $PathRoot
'[CREDENTIAL] Office 365 account: ' + $Credential.UserName | LogStamp

#Import required Azure AD module
import-module MSOnline

'[CONNECTION] Establishing PS-Session with Exchange Online' | LogStamp
$ExoSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri `
    https://outlook.office365.com/powershell-liveid/ `
    -Credential $Credential -Authentication Basic -AllowRedirection

if ($null -ne $ExoSession) {
    '[SUCCESS] Connected to Exchange Online as ' + $Credential.UserName | LogStamp
    Import-PSSession $ExoSession
} else {
    '[STOP] Unable to connect to Exchange Online. Verify stored credential, permissions and network.' | LogStamp
    Exit
}

'[CONNECTION] Establishing PS-Session with Exchange Online Protection (EOP)' | LogStamp
$EopSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri `
    https://ps.compliance.protection.outlook.com/powershell-liveid/ `
    -Credential $Credential -Authentication Basic -AllowRedirection

if ($null -ne $EopSession) {
    '[SUCCESS] Connected to Exchange Online Protection as ' + $Credential.UserName | LogStamp
    Import-PSSession $EopSession -AllowClobber
} else {
    '[STOP] Unable to connect to Exchange Online Protection. Verify stored credential, permissions and network.' | LogStamp
    Exit
}

'[CONNECTION] Establishing connection with Azure Active Directory (AAD)' | LogStamp
try {
    '[SUCCESS] Connected to Azure Active Direcotry as ' + $Credential.UserName | LogStamp
    Connect-MsolService -Credential $Credential
} catch{
    '[STOP] Unable to connect to Azure Active Directory. Verify stored credential, permissions and network.' | LogStamp
    Exit
}


#Load "System.Web" assembly in PowerShell console 
[Reflection.Assembly]::LoadWithPartialName("System.Web") 

foreach ($id in $ListMembers) {

    # reverse_user.username for each ID stores the SAMaccount Name
    $samname = $id.reverse_user.username
    "[$samname] ............. Starting Account Remediation ............." | LogStamp

    # office 365 uses UPN for account name.  Typically the users email address; user@sample.com
    # build the UPN by taking SAMaccount and adding UPN Suffix from Configuration.xml
    $upn = $samname + $Config.UpnSuffix

    # set Log path and create any missing subdirectories
    $PathAudit = $PathRoot + '\Audit\' + $upn + '-' + (Get-Date).ToString('yyyy-MM-dd') + '.log'
    $PathAudit | % { 
               If (Test-Path -Path $_) { Get-Item $_ } 
               Else { New-Item -ItemType File -Path $_ -Force } 
    } 

    # filter adds Timestamp and adds content to the Script Log
    filter AuditStamp {"$(Get-Date -Format O):$_" | Add-Content $PathAudit -Force }


    if ($Config.ReqChangePw -eq 'yes') {
        
        "[$samname] Updating require password change. Update Configuration.xml to change behavior" | LogStamp 
        Require-ChangePassword $upn

    } else {
        
        "[$samname] Skipped requiring password change. Update Configuration.xml to change behavior" | LogStamp 
    }

    if ($Config.ReqStrongPw -eq 'yes') {
        
        "[$samname] Updating require strong password. Update Configuration.xml to change behavior" | LogStamp
        Require-StrongPassword $upn

    } else {

        "[$samname] Skipped requiring strong password. Update Configuration.xml to change behavior" | LogStamp 
    }

    if ($Config.EnableMfa -eq 'yes') {
        
        "[$samname] Updating enabling multi-factor authentication (MFA). Update Configuration.xml to change behavior" | LogStamp
        Enable-MFA $upn

    } else {
        
        "[$samname] Skipped enabling multi-factor authentication (MFA). Update Configuration.xml to change behavior" | LogStamp 
    }

    if ($Config.ResetPw -eq 'yes') {

        "[$samname] Changing account password. See audit log for new password." | LogStamp
        Reset-Password $upn

    } else {

        "[$samname] Skipped changing password. Update Configuration.xml to change behavior" | LogStamp 
    }

    if ($Config.EnableMailboxAudit -eq 'yes') {
        
        "[$samname] Enabling mailbox auditing. Update Configuration.xml to change behavior" | LogStamp
        Enable-MailboxAuditing $upn

    } else {

        "[$samname] Skipped enabling mailbox auditing. Update Configuration.xml to change behavior" | LogStamp 
    }

    if ($Config.RemoveMailboxDelegates -eq 'yes') {
        
        "[$samname] Removing mailbox delegates. Update Configuration.xml to change behavior" | LogStamp
        Remove-MailboxDelegates $upn

    } else {
        
        "[$samname] Skipped removing mailbox delegates. Update Configuration.xml to change behavior" | LogStamp 
    }
    
    if ($Config.DisableExternalMailboxForwardRules -eq 'yes' `
        -and $Config.RemoveExternalMailboxForwardRules -ne 'yes' ) {
        
        "[$samname] Disabling external mailbox forwarding rules. Update Configuration.xml to change behavior" | LogStamp
        Disable-MailforwardingRulesToExternalDomains $upn

    } else {
        
        "[$samname] Skipped disabling external mailbox forwarding rules. Update Configuration.xml to change behavior" | LogStamp
    }

    if ($Config.RemoveExternalMailboxForwardRules -eq 'yes') {

        "[$samname] Removing external mailbox forwarding rules. Update Configuration.xml to change behavior" | LogStamp
        Disable-MailforwardingRulesToExternalDomains $upn

    } else {

        "[$samname] Skipped removing external mailbox forwarding rules. Update Configuration.xml to change behavior" | LogStamp
    }
    
    if ($Config.DisableMailboxForward -eq 'yes') {
        
        "[$samname] Disabling mailbox forwarding. Update Configuration.xml to change behavior" | LogStamp
        Disable-MailboxForwarding $upn

    } else {
        
        "[$samname] Skipped removing mailbox forwarding. Update Configuration.xml to change behavior" | LogStamp 
    }
        
    if ($Config.GetMailboxAudit -eq 'yes') {
        
        "[$samname] Getting a mailbox audit log. Logs stored in Audit directory." | LogStamp
        Get-AuditLog $upn $PathRoot

    } else {
        
        "[$samname] Skipped getting a mailbox audit. Update Configuration.xml to change behavior" | LogStamp 
    }

    # Remove-PTRListMember $PtrKey $Config.Host $Config.ListId $id.id
}

# added to cleanup open sessions
'[DISCONNECT] Removing PS-Session with Exchange Online' | LogStamp
Remove-PSSession $ExoSession
'[DISCONNECT] Removing PS_Session with Exchange Online Portection (EOP)' | LogStamp
Remove-PSSession $EopSession

'[DISCONNECT] Exiting connection with Azure Active Directory (AAD)' | LogStamp

Exit
