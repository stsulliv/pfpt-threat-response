# Import External Scripts
. $PSScriptRoot\scripts\get-config.ps1
. $PSScriptRoot\scripts\get-key.ps1
. $PSScriptRoot\scripts\get-o365-credentials.ps1
. $PSScriptRoot\scripts\get-list-members.ps1
. $PSScriptRoot\scripts\delete-list-members.ps1
. $PSScriptRoot\scripts\o365-acct-remediations.ps1
. $PSScriptRoot\scripts\connect-exchange-online.ps1
. $PSScriptRoot\scripts\connect-exchange-online-protection.ps1

################################# Starting Main Script #################################

# set Log path and create any missing subdirectories
$PathLog = $PSScriptRoot + '\Log\script-' + (Get-Date).ToString('yyyy-MM-dd') + '.log'
$PathLog | % { 
           If (Test-Path -Path $_) { Get-Item $_ } 
           Else { New-Item -ItemType File -Path $_ -Force } 
} 

# filter adds Timestamp and adds content to the Script Log
filter LogStamp {"$(Get-Date -Format O):$_" | Add-Content $PathLog -Force }

'---------- Initializing script Configuration, Key and Credential ----------' | LogStamp

# get script configuration
$Config = ptr-Get-Config $PSScriptRoot
'Connecting to PTR host: ' + $Config.Host | LogStamp
'Referencing PTR User List ID : ' + $Config.ListId | LogStamp

# get threat response key
$PtrKey = ptr-Get-Key $PSScriptRoot
'Threat Response API Key: ending in ...' + $PtrKey.Substring($PtrKey.Length - 8, 8) | LogStamp

# get Azure credential
$Credential = ptr-get-o365-credentials $PSScriptRoot
'Using Office 365 account: ' + $Credential.UserName | LogStamp

# get members of threat response list
# script will EXIT if no members in list
$ListMembers = ptr-Get-List-Members $PtrKey $Config.Host $Config.ListId
'Number of members in PTR List: ' + $ListMembers.id.Length | LogStamp

# Connecting to Exchange Online, EOP, MSO and AAD
$ExoSession = connect-exchange-online $Credential
$EopSession = connect-exchange-online-protection $Credential

'Establishing connection with Microsoft Online (MSO)' | LogStamp

try {
    Connect-MsolService -Credential $Credential

} catch{
    '[ERROR] Unable to connect to Microsoft Online (MSO).' | LogStamp
    Exit
}

'Connected to Microsoft Online (MSO) as ' + $Credential.UserName | LogStamp

'Establishing connection with Azure Active Directory (AAD)' | LogStamp
try {
    Connect-AzureAD -Credential $Credential

} catch{
    '[STOP] Unable to connect to Azure Active Directory (AAD).' | LogStamp
    Exit
}

'Connected to Azure Active Directory as ' + $Credential.UserName | LogStamp

# Remediate each member of the list
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
    
    if ($Config.DisableExternalMailboxForwardRules -eq 'yes') {
        
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
        Get-AuditLog $upn $PSScriptRoot

    } else {
        "[SKIPPED] Getting a mailbox audit." | LogStamp 
    }

    ptr-Delete-List-Members $PtrKey $Config.Host $Config.ListId $id.id

    "............. Finished Account Remediation of $samname ............." | LogStamp
}

# added to cleanup open sessions
'[DISCONNECT] Removing PS-Session with Exchange Online' | LogStamp
Remove-PSSession -Id $ExoSession.Id

'[DISCONNECT] Removing PS_Session with Exchange Online Portection (EOP)' | LogStamp
Remove-PSSession -Id $EopSession.Id

'[DISCONNECT] Exiting connection with Azure Active Directory (AAD)' | LogStamp

Exit
