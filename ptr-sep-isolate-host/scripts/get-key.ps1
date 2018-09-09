function ptr-Get-Key ($PathRoot) {
    
    if (!([System.IO.File]::Exists("$PathRoot\threatresponse.cred"))) {
    
        $PtrKey = Read-Host -Message "Enter your API Key from Threat Response"
        $PtrKey | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File "$PathRoot\threatresponse.cred" -Force

        return $PtrKey
    }
    else {
        $PtrKeySec = Get-Content "$PathRoot\threatresponse.cred" | ConvertTo-SecureString
        $PtrKey = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((($PtrKeySec))))

        return $PtrKey
    }
}