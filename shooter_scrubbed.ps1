<#
.SYNOPSIS
    Mass remediation of vulnerable software across roaming profiles and workstations
.DESCRIPTION
    Removes specified applications from local profiles, roaming profiles, registry, and scheduled tasks
    
    *** SAFE MODE: DESTRUCTIVE OPERATIONS ARE CURRENTLY STUBBED OUT ***
    This script will only SIMULATE deletions and log what WOULD be removed.
    To enable actual remediation, search for "STUBBED FOR SAFETY" and uncomment the deletion commands.
    
.PARAMETER AppConfig
    Path to JSON config file defining applications to remove
.PARAMETER RoamingProfilePath
    UNC path to roaming profiles share (e.g., \\server\RoamingUser-Profiles$)
.PARAMETER WhatIf
    Simulate without actually removing anything
.PARAMETER ThrottleLimit
    Maximum number of parallel threads (default: 10)
#>

param(
    [string]$AppConfig = ".\targets.json",
    [string]$RoamingProfilePath = "\\192.168.123.21\RoamingUser-Profiles$",
    [switch]$WhatIf,
    [int]$ThrottleLimit = 10
)

#Requires -Version 7.0

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "remediation_$timestamp.log"

# Thread-safe logging using a synchronized hashtable
$script:logLock = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()

function Write-Log {
    param($Message, $Level = "INFO")
    $logMessage = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Write-Host $logMessage
    # Queue message for batch writing
    $script:logLock.Enqueue($logMessage)
}

function Write-LogBuffer {
    $messages = @()
    while($script:logLock.TryDequeue([ref]$null)) {
        $msg = $null
        if($script:logLock.TryDequeue([ref]$msg)) {
            $messages += $msg
        }
    }
    if($messages.Count -gt 0) {
        Add-Content -Path $logFile -Value $messages
    }
}

Write-Host "`n" -NoNewline
Write-Host "╔═══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
Write-Host "║                           SAFE MODE ENABLED                           ║" -ForegroundColor Yellow
Write-Host "║                                                                       ║" -ForegroundColor Yellow
Write-Host "║  Destructive operations are STUBBED OUT for testing purposes.         ║" -ForegroundColor Yellow
Write-Host "║  This script will only SIMULATE deletions and report findings.        ║" -ForegroundColor Yellow
Write-Host "║                                                                       ║" -ForegroundColor Yellow
Write-Host "║  To enable actual remediation, search for 'STUBBED FOR SAFETY'        ║" -ForegroundColor Yellow
Write-Host "║  and uncomment the deletion commands.                                 ║" -ForegroundColor Yellow
Write-Host "╚═══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
Write-Host "`n" -NoNewline

# Load application definitions
$config = Get-Content $AppConfig | ConvertFrom-Json

# Discover all vulnerable installations
Write-Log "Starting vulnerability discovery with $ThrottleLimit parallel threads..."
$computers = Get-ADComputer -Filter {Enabled -eq $true} | Select-Object -ExpandProperty Name
Write-Log "Found $($computers.Count) computers to scan"

$discoveryResults = $computers | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
    $comp = $_
    $config = $using:config
    $logLock = $using:logLock
    
    # Helper function for thread-safe logging
    function Write-ThreadLog {
        param($Message, $Level = "INFO")
        $logMessage = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
        Write-Host $logMessage
        $logLock.Enqueue($logMessage)
    }
    
    if(-not (Test-Connection -ComputerName $comp -Count 1 -Quiet -TimeoutSeconds 2)) {
        Write-ThreadLog "Skipping offline: $comp" "WARN"
        return $null
    }
    
    $computerFindings = @()
    
    try {
        $userProfiles = Get-ChildItem "\\$comp\C$\Users" -Directory -ErrorAction Stop
        
        foreach($userProfile in $userProfiles) {
            # Skip system profiles
            if($userProfile.Name -in @('Public', 'Default', 'Default User', 'All Users', 'Administrator', 'Guest', 'WDAGUtilityAccount')) { continue }
            
            $userPath = "\\$comp\C$\Users\$($userProfile.Name)"
            
            foreach($app in $config.applications) {
                $foundPaths = @()
                
                foreach($relPath in $app.paths) {
                    $fullPath = Join-Path $userPath $relPath
                    if(Test-Path $fullPath) {
                        $foundPaths += $relPath
                    }
                }
                
                if($foundPaths.Count -gt 0) {
                    $computerFindings += [PSCustomObject]@{
                        Computer = $comp
                        User = $userProfile.Name
                        Application = $app.name
                        FoundPaths = $foundPaths -join '; '
                        Timestamp = Get-Date
                    }
                }
            }
        }
        
        Write-ThreadLog "Scanned $comp : Found $($computerFindings.Count) installations"
        
        # Return an object with computer name and findings
        return [PSCustomObject]@{
            Computer = $comp
            Findings = $computerFindings
            Success = $true
        }
    } catch {
        Write-ThreadLog "Failed to scan $comp : $($_.Exception.Message)" "ERROR"
        return $null
    }
}

# Flush queued log messages
Write-LogBuffer

# Extract findings and online computers from discovery results
$findings = $discoveryResults | Where-Object { $_ -ne $null } | ForEach-Object { $_.Findings }
$onlineComputers = ($discoveryResults | Where-Object { $_ -ne $null -and $_.Success } | Select-Object -ExpandProperty Computer) -as [string[]]

Write-Log "Discovery complete. Found $($findings.Count) installations across $($onlineComputers.Count) online computers."
$findings | Export-Csv "findings_$timestamp.csv" -NoTypeInformation

# Remediation phase - only process findings from computers that were successfully discovered
Write-Log "Beginning remediation with $ThrottleLimit parallel threads..."

$remediationResults = $findings | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
    $finding = $_
    $config = $using:config
    $WhatIf = $using:WhatIf
    $RoamingProfilePath = $using:RoamingProfilePath
    $logLock = $using:logLock
    
    # Helper function for thread-safe logging
    function Write-ThreadLog {
        param($Message, $Level = "INFO")
        $logMessage = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
        Write-Host $logMessage
        $logLock.Enqueue($logMessage)
    }
    
    function Remove-PathIfExists {
        param($Path, $Description)
        
        if(Test-Path $Path) {
            if($WhatIf) {
                Write-ThreadLog "WOULD REMOVE: $Path" "WHATIF"
            } else {
                try {
                    # STUBBED FOR SAFETY - UNCOMMENT TO ENABLE ACTUAL DELETION
                    # Remove-Item $Path -Recurse -Force -ErrorAction Stop
                    Write-ThreadLog "[STUBBED] WOULD REMOVE: $Path" "WHATIF"
                    return $true
                } catch {
                    Write-ThreadLog "FAILED: $Path - $($_.Exception.Message)" "ERROR"
                    return $false
                }
            }
        }
        return $false
    }
    
    function Remove-RegistryIfExists {
        param($ComputerName, $Path)
        
        try {
            # Parse the registry path (e.g., HKLM:\Software\Company\Product)
            if($Path -match '^(HKLM|HKCU|HKCR|HKU|HKCC):\\(.+)$') {
                $hive = $Matches[1]
                $subKey = $Matches[2]
                
                # Map hive abbreviation to RegistryHive enum
                $hiveMap = @{
                    'HKLM' = [Microsoft.Win32.RegistryHive]::LocalMachine
                    'HKCU' = [Microsoft.Win32.RegistryHive]::CurrentUser
                    'HKCR' = [Microsoft.Win32.RegistryHive]::ClassesRoot
                    'HKU'  = [Microsoft.Win32.RegistryHive]::Users
                    'HKCC' = [Microsoft.Win32.RegistryHive]::CurrentConfig
                }
                
                if($WhatIf) {
                    Write-ThreadLog "WOULD REMOVE: Registry $Path on $ComputerName" "WHATIF"
                    return $true
                }
                
                # Open remote registry (uses RPC, not WinRM - requires Remote Registry service)
                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($hiveMap[$hive], $ComputerName)
                
                if($reg) {
                    # Check if key exists
                    $key = $reg.OpenSubKey($subKey, $false)
                    if($key) {
                        $key.Close()
                        # STUBBED FOR SAFETY - UNCOMMENT TO ENABLE ACTUAL DELETION
                        # $reg.DeleteSubKeyTree($subKey, $false)
                        Write-ThreadLog "[STUBBED] WOULD REMOVE: Registry $Path on $ComputerName" "WHATIF"
                        $reg.Close()
                        return $true
                    } else {
                        $reg.Close()
                        return $false
                    }
                }
            } else {
                Write-ThreadLog "Invalid registry path format: $Path" "ERROR"
                return $false
            }
        } catch [System.UnauthorizedAccessException] {
            Write-ThreadLog "Access denied to registry on $ComputerName - $Path" "ERROR"
            return $false
        } catch [System.IO.IOException] {
            Write-ThreadLog "Network/Remote Registry service error on $ComputerName - Ensure Remote Registry service is running" "WARN"
            return $false
        } catch {
            Write-ThreadLog "Registry removal failed on $ComputerName - $Path : $($_.Exception.Message)" "ERROR"
            return $false
        }
        
        return $false
    }
    
    Write-ThreadLog "Processing: $($finding.Application) on $($finding.Computer) for user $($finding.User)"
    
    $app = $config.applications | Where-Object { $_.name -eq $finding.Application }
    $result = [PSCustomObject]@{
        Computer = $finding.Computer
        User = $finding.User
        Application = $finding.Application
        LocalProfileCleaned = $false
        RoamingProfileCleaned = $false
        RegistryCleaned = $false
        ScheduledTasksCleaned = $false
        Errors = @()
    }
    
    # 1. Clean local workstation profile
    foreach($relPath in $app.paths) {
        $fullPath = "\\$($finding.Computer)\C$\Users\$($finding.User)\$relPath"
        if(Remove-PathIfExists -Path $fullPath -Description "Local: $relPath") {
            $result.LocalProfileCleaned = $true
        }
    }
    
    # 2. Clean roaming profile if it exists
    $roamingUserPath = Join-Path $RoamingProfilePath $finding.User
    if(Test-Path $roamingUserPath) {
        foreach($relPath in $app.paths) {
            $fullPath = Join-Path $roamingUserPath $relPath
            if(Remove-PathIfExists -Path $fullPath -Description "Roaming: $relPath") {
                $result.RoamingProfileCleaned = $true
            }
        }
    }
    
    # 3. Clean registry
    foreach($regPath in $app.registry) {
        if(Remove-RegistryIfExists -ComputerName $finding.Computer -Path $regPath) {
            $result.RegistryCleaned = $true
        }
    }
    
    # 4. Clean scheduled tasks (requires WinRM/PSRemoting)
    if($app.scheduledTasks) {
        try {
            # Test if WinRM is available on this computer
            $testSession = Test-WSMan -ComputerName $finding.Computer -ErrorAction SilentlyContinue
            
            if($testSession) {
                Invoke-Command -ComputerName $finding.Computer -ScriptBlock {
                    param($taskPatterns, $whatIf)
                    
                    foreach($pattern in $taskPatterns) {
                        $tasks = Get-ScheduledTask | Where-Object { $_.TaskName -like $pattern }
                        foreach($task in $tasks) {
                            if($whatIf) {
                                Write-Output "Would have sniped this bih: $($task.TaskName)"
                            } else {
                                # STUBBED FOR SAFETY - UNCOMMENT TO ENABLE ACTUAL DELETION
                                # Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false
                                Write-Output "[STUBBED] Would have sniped this bih: $($task.TaskName)"
                            }
                        }
                    }
                } -ArgumentList $app.scheduledTasks, $WhatIf -ErrorAction Stop
                
                $result.ScheduledTasksCleaned = $true
            } else {
                Write-ThreadLog "Skipping scheduled tasks on $($finding.Computer) - WinRM not available. Use a GPO instead. $($_.Exception.Message)" "WARN"
                $result.Errors += "Scheduled tasks skipped - WinRM not enabled. Use a GPO instead. $($_.Exception.Message)"
            }
        } catch {
            Write-ThreadLog "Scheduled task cleanup failed on $($finding.Computer): $($_.Exception.Message)" "WARN"
            $result.Errors += "Scheduled tasks: $($_.Exception.Message)"
        }
    }
    
    return $result
}

# Flush queued log messages
Write-LogBuffer

# Generate final report
Write-Log "Remediation complete. Generating report..."
Write-LogBuffer
$remediationResults | Export-Csv "remediation_$timestamp.csv" -NoTypeInformation

$summary = @"

=== REMEDIATION SUMMARY ===
Total Installations Found: $($findings.Count)
Total Computers Affected: $($findings | Select-Object -Unique Computer | Measure-Object | Select-Object -ExpandProperty Count)
Total Users Affected: $($findings | Select-Object -Unique User | Measure-Object | Select-Object -ExpandProperty Count)

Applications Remediated:
$($findings | Group-Object Application | ForEach-Object { "  - $($_.Name): $($_.Count) installations" })

Success Metrics:
  - Local Profiles Cleaned: $($remediationResults | Where-Object LocalProfileCleaned | Measure-Object | Select-Object -ExpandProperty Count)
  - Roaming Profiles Cleaned: $($remediationResults | Where-Object RoamingProfileCleaned | Measure-Object | Select-Object -ExpandProperty Count)
  - Registry Cleaned: $($remediationResults | Where-Object RegistryCleaned | Measure-Object | Select-Object -ExpandProperty Count)
  - Scheduled Tasks Cleaned: $($remediationResults | Where-Object ScheduledTasksCleaned | Measure-Object | Select-Object -ExpandProperty Count)

Errors Encountered: $($remediationResults.Errors | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count)

Log File: $logFile
Findings: findings_$timestamp.csv
Results: remediation_$timestamp.csv
"@

Write-Log $summary
Write-LogBuffer
$summary | Out-File "summary_$timestamp.txt"

Write-Host "`n$summary" -ForegroundColor Cyan 