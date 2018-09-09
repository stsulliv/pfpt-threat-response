function ptr-delete-list-members ($ptr_key, $ptr_host, $ptr_list, $member_id) {
    
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