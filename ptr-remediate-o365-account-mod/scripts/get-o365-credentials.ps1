function ptr-get-o365-credentials ($PathRoot) {
    
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