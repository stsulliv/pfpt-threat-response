function connect-exchange-online-protection ($Credential) {

    # Connecting to Exchange Online
    'Establishing PS-Session with Exchange Online Protection (EOP)' | LogStamp
    $EopSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri `
        https://ps.compliance.protection.outlook.com/powershell-liveid/ `
        -Credential $Credential -Authentication Basic -AllowRedirection

    try { 
        Import-PSSession $EopSession -DisableNameChecking -AllowClobber | LogStamp

    } catch {
        '[ERROR] Unable to connect to Exchange Online Protection.' | LogStamp
        Exit
    }

    'Connected to Exchange Online Protection as ' + $Credential.UserName | LogStamp

    return $EopSession
}
