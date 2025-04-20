


Using module ".\Target.psm1"
Using module ".\FirewallManager.psm1"

# Import-Module -Name "$PSScriptRoot\Target.psm1"   -Force -Verbose
# Import-Module -Name "$PSScriptRoot\FirewallManager.psm1" -Force -Verbose
Write-Host "Imported IFirewall"


# # Define a class to manage global paths
# class Global {
#     static [string] $TargetClass
#     static [string] $FirewallClass

#     static [void] Initialize() {
#         # Use $PSScriptRoot to set full paths to supporting .psm1 files
#         Write-Host "Importing..."
#         [Global]::TargetClass   = Join-Path -Path $PSScriptRoot -ChildPath "Target.psm1"
#         [Global]::FirewallClass = Join-Path -Path $PSScriptRoot -ChildPath "Firewall.psm1"
#         Write-Host "Imported"
#     }

#     Global() {}
# }

# # Initialize global paths
# [Global]::Initialize()
# Write-Host "one"

# # Import Target.psm1
# if (Test-Path -Path ([Global]::TargetClass)) {
#     Write-Verbose "Importing Target.psm1 from $([Global]::TargetClass)"
#     Import-Module -Name ([Global]::TargetClass) -Force -Verbose
# } else {
#     Write-Output "File not found: $([Global]::TargetClass)"
#     return
# }

# # Import Firewall.psm1
# if (Test-Path -Path ([Global]::FirewallClass)) {
#     Write-Verbose "Importing Firewall.psm1 from $([Global]::FirewallClass)"
#     Import-Module -Name ([Global]::FirewallClass) -Force -Verbose
# } else {
#     Write-Output "File not found: $([Global]::FirewallClass)"
#     return
# }