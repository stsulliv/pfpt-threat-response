# Import External Scripts
. $PSScriptRoot\scripts\get-config.ps1
. $PSScriptRoot\scripts\get-key.ps1
. $PSScriptRoot\scripts\get-ad-credentials.ps1
. $PSScriptRoot\scripts\get-list-members.ps1
. $PSScriptRoot\scripts\delete-list-members.ps1
. $PSScriptRoot\scripts\exchange-acct-remediations.ps1

# Verify and Load Exchange Management Shell extensions
try {
    . 'C:\Program Files\Microsoft\Exchange Server\V15\bin\RemoteExchange.ps1'
} catch {
    'Exchange Management Shell not configured...exiting'

    exit
}

################################# Starting Main Script #################################

# set Log path and create any missing subdirectories
$PathLog = $PSScriptRoot + '\Log\script-' + (Get-Date).ToString('yyyy-MM-dd') + '.log'
$PathLog | % { 
           If (Test-Path -Path $_) { Get-Item $_ } 
           Else { New-Item -ItemType File -Path $_ -Force } 
} 

# filter adds LogStamp and adds content to the Script Log
filter LogStamp {"$(Get-Date -Format O):$_" | Add-Content $PathLog -Force }

'---------- Initializing script Configuration, Key and Credential ----------' | LogStamp

# get Exchange credential
$Credential = get-ad-credentials $PSScriptRoot
'Using Exchange AD account: ' + $Credential.UserName | LogStamp

# get script configuration
$Config = ptr-Get-Config $PSScriptRoot
'Connecting to PTR host: ' + $Config.ThreatResponseHost | LogStamp
'Referencing PTR User List ID : ' + $Config.ThreatResponseListId | LogStamp

# get threat response key
$PtrKey = ptr-Get-Key $PSScriptRoot
'Threat Response API Key: ending in ...' + $PtrKey.Substring($PtrKey.Length - 8, 8) | LogStamp

# get members of threat response list
# script will EXIT if no members in list
$ListMembers = ptr-Get-List-Members $PtrKey $Config.ThreatResponseHost $Config.ThreatResponseListId
'Number of members in PTR List: ' + $ListMembers.id.Length | LogStamp

$ExchangeUri = 'http://' + $Config.ExchangeHost + '/PowerShell/'

$ExchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ExchangeUri -Authentication Kerberos -Credential $Credential

Import-PSSession $ExchangeSession -DisableNameChecking -AllowClobber

# Remediate each member of the list
foreach ($id in $ListMembers) {

    # reverse_user.username for each ID stores the SAMaccount Name
    $samname = $id.reverse_user.username
    "............. Starting Account Remediation of $samname ............." | LogStamp

    # use a TRY and CATCH blocks to handle errors when user doesn't exist in Active Directory
    try {

        # use the SAM Account name to get the user object for AD Property updates
        $current_user = Get-ADUser -Identity $samname -properties passwordneverexpires,pwdlastset,CannotChangePassword
    }

    catch {

        "[ERROR] $samname does not exist in Active Directory" | LogStampc

        del_member $ptr_host $ptr_listid $id.id  # run the del_member function to DELETE ID

        continue
    }
    
    # start remediation tasks
    if ($Config.ReqChangePw -eq 'yes') {
         Require-ChangePassword $current_user $Config.UpdateCantChangePassword $Config.UpdatePwNeverExpire
    
    } else {
        "[SKIPPED] Requiring password change." | LogStamp 
    }

    if ($Config.ResetPw -eq 'yes') {
        Reset-Password $samname

    } else {
        "[SKIPPED] Changing password." | LogStamp 
    }

    if ($Config.RemoveMailboxDelegates -eq 'yes') {
        Remove-MailboxDelegates $samname

    } else {
        "[SKIPPED] Removing mailbox delegates." | LogStamp 
    }
    
    if ($Config.RemoveExternalMailboxForwardRules -eq 'yes') {
        Remove-MailforwardingRulesToExternalDomains $samname

    } else {
        "[SKIPPED] Removing external mailbox forwarding rules." | LogStamp
    }

    if ($Config.DisableExternalMailboxForwardRules -eq 'yes') {     
        Disable-MailforwardingRulesToExternalDomains $samname

    } else {
        "[SKIPPED] Disabling external mailbox forwarding rules." | LogStamp
    }
    
    if ($Config.DisableMailboxForward -eq 'yes') {
        Disable-MailboxForwarding $samname

    } else {
        "[SKIPPED] Removing mailbox forwarding." | LogStamp 
    }

    ptr-Delete-List-Members $PtrKey $Config.ThreatResponseHost $Config.ThreatResponseListId $id.id

    "............. Finished Account Remediation of $samname ............." | LogStamp
}

# added to cleanup open sessions
Remove-PSSession $ExchangeSession

'[DISCONNECT] Exiting script' | LogStamp

Exit