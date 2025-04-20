Write-Host "Imported Target"
Import-Module Microsoft.PowerShell.Utility -Force

class Target {
    [string]$Name
    [string]$Path
    [string]$Directory
    [string]$Owner

    Target([string]$Name, [string]$Path, [string]$Directory) {
        $This.Name = $Name
        $This.Path = $Path
        $This.Directory = $Directory
        $This.Owner = $(Get-Acl $Path).Owner
    }

    Target([Target]$Other){
        $This.Name = $Other.Name
        $This.Path = $Other.Path
        $This.Directory = $Other.Directory
        $This.Owner = $Other.Owner
    }

    [void] Whitelist() 
    {
        #Import-Module Microsoft.PowerShell.Utility -Force
        try
        {
            Write-Host "Whitelisting"
            Write-Host "File: $($This.Name)"
            Write-Host "Path: $($This.Path)"
            Write-Host ""

            $InName  = "$($This.Name) In    - $($This.Path))"
            $OutName = "$($This.Name) Out   - $($This.Path))"

            netsh advfirewall firewall add rule name="$InName"  dir=in  action=allow program="$($This.Path)" enable=yes
            netsh advfirewall firewall add rule name="$OutName" dir=out action=allow program="$($This.Path)" enable=yes
        }catch{
            #Write-Host "Failed to Whitelist: $($This.Path)"
            Write-Host "Error: $($_.Exception.Message)"
        }
    }

    [string] ToString() {
        $Out  = "Name: $($This.Name)`n"
        $Out += "    Path: $($This.Path)`n"
        $Out += "    Directory: $($This.Directory)`n"
        $Out += "`n"
        return $Out
    }

    [bool] Equals([object]$other) {
        if ($null -eq $other -or -not ($other -is [Target])) {
            return $false
        }
        return $This.Name -eq $other.Name
    }

    [int] GetHashCode() {
        return $This.Name.GetHashCode()
    }
}
