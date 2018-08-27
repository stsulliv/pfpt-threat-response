function ptr-Get-List-Members ($ptr_key,$ptr_host,$ptr_list) {

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