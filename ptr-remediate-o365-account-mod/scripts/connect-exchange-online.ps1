function connect-exchange-online ($Credential) {

    # Connecting to Exchange Online
    'Establishing PS-Session with Exchange Online' | LogStamp
    $ExoSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri `
        https://outlook.office365.com/powershell-liveid/ `
        -Credential $Credential -Authentication Basic -AllowRedirection

    try {
    
        Import-PSSession $ExoSession -DisableNameChecking -AllowClobber | LogStamp
    }

    catch {
        
        '[ERROR] Unable to connect to Exchange Online.' | LogStamp
        Exit
    }

    'Connected to Exchange Online as ' + $Credential.UserName | LogStamp

    return $ExoSession
}
