# Import External Scripts
. $PSScriptRoot\scripts\get-config.ps1
. $PSScriptRoot\scripts\get-key.ps1
. $PSScriptRoot\scripts\get-sep-password.ps1
. $PSScriptRoot\scripts\get-list-members.ps1
. $PSScriptRoot\scripts\delete-list-members.ps1

################################# Starting Main Script #################################

clear

# set Log path and create any missing subdirectories
$PathLog = $PSScriptRoot + '\Log\script-' + (Get-Date).ToString('yyyy-MM-dd') + '.log'
$PathLog | % { 
           If (Test-Path -Path $_) { Get-Item $_ } 
           Else { New-Item -ItemType File -Path $_ -Force } 
} 

# filter adds Timestamp and adds content to the Script Log
filter LogStamp {"$(Get-Date -Format O):$_" | Add-Content $PathLog -Force }

'---------- Initializing script Configuration, Key and Credential ----------' | LogStamp

# get threat response key
$PtrKey = ptr-Get-Key $PSScriptRoot
'Threat Response API Key: ending in ...' + $PtrKey.Substring($PtrKey.Length - 8, 8) | LogStamp

# get script configuration
$Config = ptr-Get-Config $PSScriptRoot
'Connecting to PTR host: ' + $Config.PTR_Host | LogStamp
'Referencing PTR User List ID : ' + $Config.PTR_ListId | LogStamp
'Using SEP account: ' + $Config.SEP_Admin | LogStamp

$SEP_Username = $Config.SEP_Admin
$SEP_Password = get-sep-password $PSScriptRoot

# get members of threat response list
# script will EXIT if no members in list
$ListMembers = ptr-Get-List-Members $PtrKey $Config.PTR_Host $Config.PTR_ListId
'Number of members in PTR List: ' + $ListMembers.id.Length | LogStamp

# required to get around Certificate errors
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;

# build the Credential headers for the jason request
$cred= @{
username = $SEP_Username
password = $SEP_Password
domain = ""
}

# converts $cred array to json to send to the SEPM
$auth = $cred | ConvertTo-Json

# build Authentication URL
$auth_url = 'https://' + $Config.SEP_Host + ':8446/sepm/api/v1/identity/authenticate'
'Connecting to REST URI ' + $auth_url

# Get SEP Authentication TOKEN for future calls
try {
    $SEPauth = Invoke-RestMethod -Method Post -Uri $auth_url -Body $auth -ContentType 'application/json'

} catch {
    'Connection FAILED. Script exiting.' | LogStamp

    # exit the script
    exit
}

'Connection to REST API returned token ' + $SEPauth.token | LogStamp

# build SEP authentication header
$header =@{
Authorization = 'Bearer '+ $SEPauth.token
}

# Remediate each member of the list
foreach ($id in $ListMembers) {

    # reverse_user.username for each ID stores the SAMaccount Name
    $hostfqdn = $id.host.host
    $hostname = $hostfqdn.Split(".")[0]

    "............. Starting Account Remediation of $hostname ............." | LogStamp

    # build Computers URL
    $computers_url = 'https://' + $Config.SEP_Host + ':8446/sepm/api/v1/computers?computerName=' + $hostname

    'Connecting to REST URI ' + $computers_url | LogStamp

    try {
        $computer = Invoke-RestMethod -Method Get -Uri $computers_url -Headers $header
    
    } catch {
        "Connection FAILED. Script exiting." | LogStamp

        # go to next item in list
        break;
    }

    $comphardwarekey = $computer -match '.*"hardwareKey":"(\w+)".*'

    if ($comphardwarekey) {    
    
        $hardwareKey = $matches[1]
    
    } else {
        'No hardware key returned. Script exiting' | LogStamp
    }

    "Connection to REST API returned hardwareKey $hardwarekey" | LogStamp

    'Moving SEP Endpoint to Quarantine group with ID ' + $Config.SEP_ListId | LogStamp

    # Build the PATCH body to move client.  Includes destination group ID and Client HardwareKey
    $update = '[{"group":{"id":"' + $Config.SEP_ListId + '"},"hardwareKey":"' + $hardwareKey + '"}]'

    Invoke-RestMethod -Uri $computers_url -Method Patch -Body $update -ContentType 'application/json' -Headers $header

    ptr-Delete-List-Members $PtrKey $Config.PTR_Host $Config.PTR_ListId $id.id
}