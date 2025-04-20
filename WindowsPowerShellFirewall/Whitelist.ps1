# Using module IFirewall
Using module ".\IFirewall\Target.psm1"
Using module ".\IFirewall\FirewallManager.psm1"
using namespace System.Collections.Generic

param(
    [switch]$OnlySetWhitelist,
    [switch]$WhitelistAllStandards,
    [switch]$WhitelistWindowsCore,
    [switch]$WhitelistWindowsServices,
    [switch]$CleanOutDuplicates,
    [switch]$WhitelistProgramFilesAndApps,
    [switch]$CleanupWinSxS,
    [string]$WhitelistFolder,
    [string]$WhitelistFile,
    [switch]$TurnON,
    [switch]$TurnOFF
)
# $ErrorActionPreference = "Stop"
Import-Module Microsoft.PowerShell.Utility -Force
# Import-Module -Name "$PSScriptRoot\IFirewall\FirewallManager.psm1" -Force -Verbose

# Check for most recent version
$currentVersion = $PSVersionTable.PSVersion
$requiredVersion = [version]"7.5.0"
if ($currentVersion -lt $requiredVersion) {
    Write-Host "PowerShell version 7.5 or higher is required. Current version: $currentVersion"
    Exit
}

# Import-Module -Name ".\Global.psm1" -Force -Verbose
# [Global]::Initialize()
# Add-Type -AssemblyName System.Management.Automation

if ($PSBoundParameters.Count -eq 0) {
    Write-Host "No arguments were provided. Here are your options:"
        $MyInvocation.MyCommand.Parameters.GetEnumerator() | ForEach-Object {
        $ParamName = $_.Key
        $ParamType = $_.Value.ParameterType.Name
        Write-Host "  - $ParamName : [$ParamType]"
    }
    Exit
}

# Warning!! $CleanupWinSxS, not included in $WhitelistAllStandards and should be run at least once!!
if ($WhitelistAllStandards){
    $WhitelistWindowsCore = $true
    $WhitelistWindowsServices = $true
    $WhitelistProgramFilesAndApps = $true
    $CleanOutDuplicates = $true
}

Write-Host "Running script with the following parameters:"
$PSBoundParameters.GetEnumerator() | ForEach-Object {
    Write-Host "    $($_.Key): $($_.Value)"
}


$FirewallManager = [FirewallManager]::new()
# $FirewallManager = Get-FirewallManager

if ($TurnON){
    $FirewallManager.TurnOn()
    return
}

if ($TurnOFF){
    $FirewallManager.TurnOFF()
    return
}

if ($OnlySetWhitelist -ne $true)
{
    if($CleanupWinSxS)            { $FirewallManager.CleanupWinSxS() }
    if($WhitelistWindowsCore)     { $FirewallManager.WhitelistWindowsByTrustedOwnership() }
    if($WhitelistWindowsServices) { $FirewallManager.WhitelisMicrosoftServices() }

    if($WhitelistProgramFilesAndApps)
    {
        $FirewallManager.WhitelistByFolderAndOwnership("C:\program files")
        $FirewallManager.WhitelistByFolderAndOwnership("C:\program files (x86)")
        $FirewallManager.WhitelistByFolderAndOwnership("C:\Program Files\WindowsApps") # Hidden Folder
    }
    $MyOwnership = "$env:COMPUTERNAME\$env:USERNAME"
    $Owners = [List[string]]::new()
    $Owners.Add($MyOwnership)
    if($WhitelistFolder.Length -gt 0){ $FirewallManager.WhitelistByFolderAndOwnership($WhitelistFolder, $Owners) }
    if($WhitelistFile.Length   -gt 0){ $FirewallManager.WhitelistFile($WhitelistFile) }
}

if($CleanOutDuplicates){ $firewallmanager.CleanOutFirewallDuplicates() }

Write-Host "Finished Whitelisting!!"

