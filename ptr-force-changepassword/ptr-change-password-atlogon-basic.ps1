# import modules
Import-Module ActiveDirectory

# Change the value below to reflect your requirements
$ptr_host = 'https://host.example.com/'  # change to PTR Host/FQDN
$ptr_list = '4'  # Update to reflect PTR List ID
$ptr_auth = '111a1111-2223-333e-4ea4-55555555ee5e'  # the PTR key
$ptr_log = ".\ptr-logs.txt"  
$vrb_log = $TRUE  # $TRUE logs every run of the script, $FALSE only log runs when PTR List is not empty
$ad_update = $TRUE  # $TRUE will update AD properties PasswordNeverExpires and CannotChangePassword
$list_update = $TRUE  # $TRUE will delete non-AD User from the PTR list
$CatchPreference = 'Stop'


filter timestamp {"$(Get-Date -Format O):$_" | Add-Content $ptr_log }  # set timestamp filter

# required to get around Certificate errors
$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

# build PTR headers for the REST API request
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Accept", 'application/json')
$headers.Add("Authorization", $ptr_auth)

# functionto DELETE member of a list by ID
function del_member ($id) {
    $url_delete_member = "${ptr_host}api/lists/${ptr_list}/members/${id}.json"  # build DELETE url

    $response = Invoke-RestMethod -Method Delete -Uri $url_delete_member -Headers $headers

    "[UPDATE] $samname with id:${id} DELETED from list #${ptr_list}" | timestamp
}

# gets a list of all members if the group from Threat Response
# use TRY and CATCH incase URL or AUTH fail
try {
    $url_get_members = "${ptr_host}api/lists/${ptr_list}/members.json"  # build GET URL
    
    # GET the members of the LIST
    $members = Invoke-RestMethod -Method Get -Uri $url_get_members -Headers $headers
    $num_members = $members.Length

    if ($num_members -gt 0 -or $vrb_log) {

        "[INFO] GET from list #${ptr_list} returned $num_members members" | timestamp
    }
}

catch {
    "[ERROR] GET request $url_get_members FAILED" | timestamp
    
    $CatchPreference  # stop script on URL error
}

foreach ($id in $members) {

    # json.reverse_user.username stores the SAMaccount Name
    $samname = $id.reverse_user.username
    $continue = $TRUE  # if USER doesn't meet requirements set to false

    # use a TRY and CATCH blocks to handle errors when user doesn't exist in Active Directory
    try {

        # use the SAM Account name to get the user object for AD Property updates
        $current_user = Get-ADUser -Identity $samname -properties passwordneverexpires,pwdlastset,CannotChangePassword
    }

    catch {

        "[ERROR] $samname does not exist in Active Directory" | timestamp

        $continue = $FALSE  # mark as doesn't meet requirements

        if ($list_update -eq $TRUE) {

            del_member ($id.id)
        }
    }
    
    # check is ChangePasswordNextLogon is aleady true
    if ($current_user.ChangePasswordAtLogon -eq 'True' -AND $continue) {

        "[INFO] $samname AD property ChangePasswordAtLogon is $TRUE" | timestamp

        $continue = $FALSE  # mark as doesn't meet requirements
    }

    # In order to set "ChangePasswordNextLogon" to $TRUE, user's cannot be prevented form changing password
    if ($current_user.CannotChangePassword -eq 'True' -AND $continue) {

        # if $ad_update is set to TRUE, the user property ChangePasswordNextLogon will be set to $false.
        if ($ad_update -eq $TRUE) {

            Set-ADUser -Identity $samname -CannotChangePassword:$false

            "[UPDATE] $samname AD property UserCannotChangePassword UPDATED to $FALSE" | timestamp
        }
        # else write warning to console
        else {

            "[WARNING] $samname AD property UserCannotChangePassword is $TRUE" | timestamp

            $continue = $FALSE  # mark as doesn't meet requirements
        }
    }

    # In order to set "ChangePasswordNextLogon" to $TRUE, user's password cannot be set to Never Expires
    if ($current_user.PasswordNeverExpires -eq 'True' -AND $continue) {

        if ($ad_update -eq $TRUE) {

            Set-ADUser -Identity $samname -PasswordNeverExpires:$false

            "[INFO] $samname AD property PasswordNeverExpires UPDATED to FALSE" | timestamp
        }
        else {

            "[ERROR] $samname AD property PasswordNeverExpires is TRUE" | timestamp

            $continue = $FALSE  # mark as doesn't meet requirements
        }
    }

    # set the AD property to force change password
    if ($continue) {

        try {
            
            Set-ADUser -Identity $samname -ChangePasswordAtLogon:$true

            del_member($id.id)  # run the del_member function to DELETE ID

            "[UPDATE] $samname AD property ChangePasswordAtLogon UPDATED to $TRUE" | timestamp
        }

        catch {

            "[ERROR] $samname set AD property ChangePasswordAtLogon failed" | timestamp
        }
    }
}
