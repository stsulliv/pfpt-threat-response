function get-sep-password ($PathRoot) {
    
    if (!([System.IO.File]::Exists("$PathRoot\sepadmin.cred"))) {
    
        $SEPpwd = Read-Host 'Enter SEP Admin Password'
        $SEPpwd | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File "$PathRoot\sepadmin.cred" -Force

        return $SEPpwd
    }
    else {
        $SEPpwdSec = Get-Content "$PathRoot\sepadmin.cred" | ConvertTo-SecureString
        $SEPpwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((($SEPpwdSec))))

        return $SEPpwd
    }
}