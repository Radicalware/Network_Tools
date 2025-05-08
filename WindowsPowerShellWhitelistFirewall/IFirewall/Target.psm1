Write-Host "Imported Target"
Import-Module Microsoft.PowerShell.Utility -Force

class Target {
    [string]$File
    [string]$Path
    [string]$Owner

    Target([string]$Path) {
        if (!(Test-Path $Path)) {
            throw "Error File Absent: '$Path'"
        }

        $This.File = "$([System.IO.Path]::GetFileName($Path))"
        $This.Path = $Path
        $This.Owner = $(Get-Acl $Path).Owner
    }

    Target([Target]$Other){
        $This.File = $Other.File
        $This.Path = $Other.Path
        $This.Owner = $Other.Owner
    }

    [void] Whitelist() 
    {
        #Import-Module Microsoft.PowerShell.Utility -Force
        try
        {
            Write-Host "Whitelisting"
            Write-Host "File: `"$($This.File)`""
            Write-Host "Path: `"$($This.Path)`""
            Write-Host ""

            $InFile  = "$($This.File) In    - ($($This.Path))"
            $OutFile = "$($This.File) Out   - ($($This.Path))"

            netsh advfirewall firewall add rule name="$InFile"  dir=in  action=allow program="$($This.Path)" enable=yes
            netsh advfirewall firewall add rule name="$OutFile" dir=out action=allow program="$($This.Path)" enable=yes
        }catch{
            #Write-Host "Failed to Whitelist: $($This.Path)"
            Write-Host "Error: $($_.Exception.Message)"
        }
    }

    [string] ToString() {
        $Out  = "File: $($This.File)`n"
        $Out += "Path: $($This.Path)`n"
        $Out += "`n"
        return $Out
    }

    [bool] Equals([object]$other) {
        if ($null -eq $other -or -not ($other -is [Target])) {
            return $false
        }
        return $This.File -eq $other.File
    }

    [int] GetHashCode() {
        return $This.File.GetHashCode()
    }
}
