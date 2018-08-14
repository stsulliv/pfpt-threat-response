# No Imports

$PathRoot = $PSScriptRoot

# function stores or loads script variables
# see https://ugliscripts.com/storing-script-variables for details on Get-Variables
function Get-Variables ($PathRoot) {
    
    if (!([System.IO.File]::Exists("$PathRoot\configuration.xml"))) {
    
        $ptr_host = Read-Host 'Please enter the FQDN or IP of you Threat Response Server'
        $ptr_list_id = Read-Host 'Enter the Threat Response user list ID'
        
        # $TRUE will update AD properties PasswordNeverExpires and CannotChangePassword
        $ad_update = Read-Host 'Update PassWordNeverExpires and CannotChangePassword if needed ($TRUE/$FALSE)'
        
        # $TRUE will delete non-AD User from the PTR list
        $list_update = Read-Host 'Delete non-AD users from PTR list ($TRUE/$FALSE)'
       

        $Config =@{Host=$ptr_host;
                    ListId=$ptr_list_id;
                    ADPrereqUpdates=$ad_update;
                    RemoveNonAdUsers=$list_update}
        
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
function Get-Secret ($path) {
    
    # check if secure file already exists, if not create one
    if (!([System.IO.File]::Exists("$path\threat_response.key"))) {
        
        Write-Host 'storing secret ...'

        $secret = Read-Host 'Enter your Threat Response API Key'
        $secret | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File "$path\threat_response.key" -Force

        return $secret
    }
    else {
        
        Write-Host 'loading secret ...'
        
        $secret_encrypted = Get-Content "$path\threat_response.key" | ConvertTo-SecureString
        $secret = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((($secret_encrypted))))

        return $secret
    }
}

# functionto DELETE member of a list by ID
function del_member ($ptr_host, $ptr_listid,$ptr_memberid) {
    $url_delete_member = "https://$ptr_host/api/lists/$ptr_listid/members/$ptr_memberid.json"  # build DELETE url

    $response = Invoke-RestMethod -Method Delete -Uri $url_delete_member -Headers $headers

    "[UPDATE] $samname with id:$ptr_memberid DELETED from list #$ptr_listid" | timestamp
}

################################# Starting Main Script #################################

# sets up filter used to log messages
$PathLog = $PathRoot + '\Log\' + (Get-Date).ToString('yyyy-MM-dd') + 'ps-changepassword.log'

# create log path if it does not exist.
$PathLog | % { 
           If (Test-Path -Path $_) { Get-Item $_ } 
           Else { New-Item -ItemType File -Path $_ -Force } 
} 

# simple filter when used puts on timestamp and logs message to file
filter timestamp {"$(Get-Date -Format O):$_" | Add-Content $PathLog }  # set timestamp filter

$Config = Get-Variables $PathRoot

# set Threat Response host
$ptr_host = $Config.Host

'[CONFIGURATION] Connecting to PTR host: ' + $ptr_host | timestamp

# set Threat Response List Id
$ptr_listid = $Config.ListId

'[CONFIGURATION] Referencing PTR User List ID : ' + $ptr_listid | timestamp

# set Threat Response Key
$ptr_key = Get-Secret $PathRoot

'[CREDENTIAL] Threat Response API Key: ending in ...' + $ptr_key.Substring($ptr_key.Length - 5, 5) | timestamp

# build GET URL
$url_get_members = "https://$ptr_host/api/lists/$ptr_listid/members.json"

# required to get around Certificate errors
$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

# build PTR headers for the REST API request
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Accept", 'application/json')
$headers.Add("Authorization", $ptr_key)

# gets a list of all members if the group from Threat Response
# use TRY and CATCH incase URL or AUTH fail
try {
        
    # GET the members of the LIST
    $members = Invoke-RestMethod -Method Get -Uri $url_get_members -Headers $headers
}

catch {
    
    "[ERROR] GET request $url_get_members FAILED" | timestamp
    
    exit
}

"[INFO] GET from list #$ptr_listid returned " + $members.Length + " members" | timestamp

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

            del_member $ptr_host $ptr_listid $id.id  # run the del_member function to DELETE ID
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
        if ($Config.ADPrereqUpdates -eq $TRUE) {

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

        if ($Config.ADPrereqUpdates -eq $TRUE) {

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

            del_member $ptr_host $ptr_listid $id.id  # run the del_member function to DELETE ID

            "[UPDATE] $samname AD property ChangePasswordAtLogon UPDATED to $TRUE" | timestamp
        }

        catch {

            "[ERROR] $samname set AD property ChangePasswordAtLogon failed" | timestamp
        }
    }
}

exit
