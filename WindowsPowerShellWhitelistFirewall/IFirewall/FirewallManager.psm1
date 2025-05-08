Using module ".\Target.psm1"
using namespace System.Collections.Generic
Import-Module Microsoft.PowerShell.Utility -Force
Write-Host "Imported Firewall"

class FirewallManager 
{
    static [string] $SsDirSplitPattern = "^(.*)\\([^\\]+\.(exe|dll|bat|ps1))$" 
    static [string] $SsExteions        =            "^.*\.(exe)$" 
    #static [string] $SsExteions        =            "^.*\.(exe|dll|bat|ps1)$" 

    [List[string]]$TrustedOwners = [List[string]]::new()

    static FirewallManager() {
        Import-Module -Name "$PSScriptRoot\Target.psm1" -Force
        Import-Module Microsoft.PowerShell.Utility -Force
    }
    FirewallManager() {
        Import-Module -Name "$PSScriptRoot\Target.psm1" -Force
        Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Block
        $This.TrustedOwners.Add("NT SERVICE\TrustedInstaller")
        $This.TrustedOwners.Add("BUILTIN\Administrators")
        $This.TrustedOwners.Add("NT AUTHORITY\SYSTEM")
    }

    [void] WhitelistUsedApps([Bool] $FbWhitelist)
    {
        $LvUsedApps = [List[string]]::new()

        foreach($LoProcess in Get-Process){
            $LvUsedApps.Add($LoProcess.Path)
        }

        $UniqueApps = [HashSet[String]]::new($LvUsedApps)

        $ApproveAppsPath = "$PSScriptRoot\Config\ApprovedApps.txt"
        $DenyAppsPath    = "$PSScriptRoot\Config\DenyApps.txt"
        if (!(Test-Path $ApproveAppsPath)){ 
            New-Item -ItemType File -Path $ApproveAppsPath -Force 
        }
        if (!(Test-Path $DenyAppsPath)){ 
            New-Item -ItemType File -Path $DenyAppsPath -Force 
        }
        
        $LsApprovedApps = $(Get-Content $ApproveAppsPath)
        $LvApprovedApps = @()
        if ($null -ne $LsApprovedApps)
        {
            if ($LsApprovedApps.Contains("`n")){
                $LvApprovedApps = $LsApprovedApps.split("`n")
            } elseif ($LsApprovedApps.Length -gt 0){
                $LvApprovedApps += $LsApprovedApps
            }
        }

        $LsDenyedApps = $(Get-Content $DenyAppsPath)
        $LvDenyedApps = @()
        if ($null -ne $LsDenyedApps)
        {
            if($LsDenyedApps.Contains("`n")){
                $LvDenyedApps = $LsDenyedApps.split("`n")
            } elseif ($LsDenyedApps.Length -gt 0){
                $LvDenyedApps += $LsDenyedApps
            }
        }

        $LvTargets = [List[Target]]::new()

        Write-Host "`n`n"
        $LbNewConnection = $false
        foreach ($LsFullPath in $UniqueApps) {
            if (!(Test-Path $LsFullPath)){ 
                continue
            }
            if (($LvApprovedApps -notcontains $LsFullPath) -and ($LvDenyedApps -notcontains $LsFullPath)) {
                $LbNewConnection = $true
                if($FbWhitelist){
                    Add-Content -Path $ApproveAppsPath -Value $LsFullPath
                    $LvTargets.Add([Target]::new($LsFullPath))
                }else {
                    Write-Host $LsFullPath
                }
            }
        }

        if ($LbNewConnection -eq $false){
            Write-Host "No New Connections!!"
        }
        elseif ($FbWhitelist -and $LvTargets.Count -gt 0) {
            $this.WhitelistTargets($LvTargets)
        }

        Write-Host "`n`n"
        Write-Host "Updated: $ApproveAppsPath"
    }

    [void] TurnOn()
    {
        Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Block
    }

    [void] TurnOff()
    {
        Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Allow -DefaultOutboundAction Allow
    }

    [string[]] GetPathSplit([string] $FsPath)
    {
        $LvMatches = [regex]::Match($FsPath, [FirewallManager]::SsDirSplitPattern)
        if ($LvMatches.Success) {
            $LsDirectory = $LvMatches.Groups[1].Value
            $LsEXE = $LvMatches.Groups[2].Value
            return @("$LsDirectory\$LsEXE", $LsDirectory, $LsEXE)
        }
        else {
            throw "No Match for $FsPath"
        }
    }

    [void] WhitelistFile([string]$ProgramPath) 
    {
        [Target]::new($ProgramPath).Whitelist()
    }

    [void] WhitelistFolder([string]$RuleName, [string]$ProgramDir) 
    {
        throw "Depricated: Use FirewallManager.WhitelistByFolderAndOwnership(`"Folder`")"
        Get-ChildItem -Path $ProgramDir -Filter *.exe | ForEach-Object {
            $ProgramPath = $_.FullName
            Write-Host $ProgramPath
            $this.WhitelistFile($RuleName, $ProgramPath)
        }
    }

    [string] ExtractPath([string] $InPath)
    {
        $Pattern = '"([^"]*)"'
        $Match = [regex]::Match($InPath, $Pattern)

        if ($Match.Success) {
            $ExtractedPath = $Match[0].Value -replace [regex]::Escape('"'), ''
            return $ExtractedPath
        } else {
            return $InPath
        }
    }

    [void] WhitelistTargets([List[Target]] $FoTargets)
    {
        foreach ($LoTarget in $FoTargets){
            if ($LoTarget.Path.Length -eq 0){
                continue
            }
            if ($this.TrustedOwners -contains $LoTarget.Owner) {
                $LoTarget.whitelist()
            }
            else{
                Write-Host "Unsafe Owner = $($this.$LoTarget.Owner)"
                write-Host $this.$LoTarget
            }
        }
    }

    [void] WhitelisMicrosoftServices()
    {
        Write-Host "Whitelisting MS Services"
        $MSServices = [List[Target]]::new()
        $(Get-WmiObject Win32_Service) | ForEach-Object {
            $ServicePath = $This.ExtractPath($_.PathName)
            $LoDirConfig = $This.GetPathSplit($ServicePath)
            $FullPath = $LoDirConfig[0]
            # $Dir = $LoDirConfig[1]
            # $EXE = $LoDirConfig[2]
            $MSServices.Add([Target]::new($FullPath))
        }
        
        $LvEnumerable = [System.Linq.Enumerable]::Distinct($MSServices)
        $LvUniqueServices = [List[Target]]::new($LvEnumerable)
        $This.WhitelistTargets($LvUniqueServices) # services already have admin rights
    }

    [void] WhitelistByFolderAndOwnership([string] $BasePath)
    {
        $This.WhitelistByFolderAndOwnership($BasePath, [List[string]]::new())
    }

    [void] WhitelistByFolderAndOwnership([string] $BasePath, [List[string]] $FvOwners)
    {
        Write-Host "Whitelisting Folder: $BasePath"
        $LvAllOnwers = [System.Linq.Enumerable]::ToList($FvOwners)
        foreach ($LsOwner in $this.TrustedOwners){
            $LvAllOnwers.Add($LsOwner)
        }
        $ExeFiles = Get-ChildItem -Path $BasePath -Recurse | Where-Object { $_.Name -match [FirewallManager]::SsExteions }
        $FullTargetLine = [List[Target]]::new()
        foreach ($File in $ExeFiles) {
            $FullTargetLine.Add([Target]::new($File.FullName))
        }

        if ($FullTargetLine.Count -lt 1){
            Write-Host "No Targets for ${BasePath}"
            return
        }

        $LvEnumerable = [System.Linq.Enumerable]::Distinct($FullTargetLine)
        $TargetLine = [List[Target]]::new($LvEnumerable)

        $LvTargetMatrix = $This.Convert2dTo3d($TargetLine)
        $LnMinThreads = [Math]::Max($LvTargetMatrix.Count, 1)
        $LoRunspaceFactory = [RunspaceFactory]::CreateRunspacePool($LnMinThreads, [Environment]::ProcessorCount)
        $LoRunspaceFactory.Open()

        Write-Host "Total:  $($TargetLine.Count)"
        Write-Host "Thread: $($LvTargetMatrix.Count)"
        Write-Host "Batch:  $($LvTargetMatrix[0].Count)"

        $LvRunspaces = [List[PSCustomObject]]::new()
        $ScriptBlock = {
            param ($TargetClass, $TargetArr, $Owners)
            $TargetPath = ""
            try
            {
                Import-Module -Name "$PSScriptRoot\Target.psm1"
                foreach ($Target in $TargetArr)
                {
                    $TargetPath = $Target.Path
                    if (-not (Test-Path $TargetPath)) {
                        continue
                    }
                    # Write-Output "type: $($Target.GetType().FullName)`n"
                    if ($Owners -contains $Target.Owner) {
                        # Write-Output $Target # Write-Output In $ScriptBlock but Write-Host in $Obj.Function()  
                        $Target.Whitelist()
                        # Write-Output $Target
                    }else{
                        Write-Output "Error (Not A Trusted Owner) >> $($Target.Path) >> $($Target.Owner)`n"
                    }
                }
            }catch{
                # Write-Output "Failed to whitelist '${TargetPath}'"
                Write-Output "Error: $($_.Exception.Message) on $TargetPath"
            }
        }

        # write-Host [Global]::TargetClass
        foreach ($TargetArr in $LvTargetMatrix) {
            $LoRunspace = [powershell]::Create().AddScript($ScriptBlock)
            $LoRunspace.AddArgument("$PSScriptRoot\Target.psm1")
            $LoRunspace.AddArgument($TargetArr)
            $LoRunspace.AddArgument($LvAllOnwers)
            $LoRunspace.RunspacePool = $LoRunspaceFactory
            $LvRunspaces.Add([PSCustomObject]@{ Pipe = $LoRunspace; Status = $LoRunspace.BeginInvoke() })
        }

        $LvResults = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
        foreach ($LoRunspace in $LvRunspaces) {
            $LsOutput = $LoRunspace.Pipe.EndInvoke($LoRunspace.Status)
            $LoRunspace.Pipe.Dispose()
            $LvResults.Add($LsOutput)  # Add results in a thread-safe way
        }
        $LoRunspaceFactory.Close()
        $LoRunspaceFactory.Dispose()
        foreach($LsResult in $LvResults){
            Write-Host $LsResult
        }
    }

    [void] CleanupWinSxS()
    {
        Write-Host "Cleaning Up System Images WinSxS"
        Dism.exe /online /Cleanup-Image /StartComponentCleanup
    }

    [void] WhitelistWindowsByTrustedOwnership()
    {
        Write-Host "Whitelist by Trusted Ownership"
        $This.WhitelistByFolderAndOwnership("C:\Windows", $This.TrustedOwners)
    }

    [void] CleanOutFirewallDuplicates()
    {
        $LvGroupedFirewallRules = Get-NetFirewallRule | Group-Object -Property DisplayName, Direction, Action, Enabled, Profile, LocalAddress, LocalPort, RemoteAddress, RemotePort, Protocol
        foreach ($LvGropu in $LvGroupedFirewallRules) {
            if ($LvGropu.Count -gt 1) {
                $LvGropu.Group | Select-Object -Skip 1 | Remove-NetFirewallRule
            }
        }
    }

    [List[List[Target]]] Convert2dTo3d([List[Target]] $FvTargets)
    {
        $ChunkSize = [Math]::Ceiling($FvTargets.Count / [Environment]::ProcessorCount)
        $LvMatrix = [List[List[Target]]]::new()
        for ($t = 0; $t -lt [Environment]::ProcessorCount; $t += 1){
            $LvChucnk = [List[Target]]::new()
            for ($c = 0; $c -lt $ChunkSize; $c += 1){
                $LnIdx = ($t * $ChunkSize) + $c
                if ($LnIdx -ge $FvTargets.Count){
                    break
                }
                $LvChucnk.Add($FvTargets[$LnIdx])
            }
            if ($LvChucnk.Count -gt 0){
                $LvMatrix.Add($LvChucnk)
            }
        }
        return $LvMatrix
    }
}
