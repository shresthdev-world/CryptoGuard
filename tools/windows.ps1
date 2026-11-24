$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$target = $env:DETECTOR_REVIEW_FILE
$Mode = $env:DETECTOR_QUERY

function DirectTarget([string]$command) {
    if (-not $command -or -not $target) { return $false }
    $line = [Environment]::ExpandEnvironmentVariables($command).Trim()
    if ($line -match '^"([^"]+)"') { return $Matches[1] -ieq $target }
    return ($line -ieq $target) -or $line.StartsWith($target + ' ', [StringComparison]::OrdinalIgnoreCase)
}

switch ($Mode) {
    'gpu' {
        $values = @{}
        $engines = @(Get-CimInstance Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine)
        if ($engines.Count -eq 0) { throw 'GPU engine counters unavailable' }
        foreach ($engine in $engines) {
            if ($engine.Name -match '^pid_(\d+)_') {
                $key = $Matches[1]
                $value = [double]$engine.UtilizationPercentage
                if ($value -gt [double]$values[$key]) { $values[$key] = $value }
            }
        }
        ConvertTo-Json -Compress -InputObject $values
    }
    'dns' {
        $rows = @(Get-DnsClientCache | Where-Object { $_.Type -in 1,28 } |
            Select-Object Entry,Data)
        ConvertTo-Json -Compress -InputObject $rows
    }
    'review' {
        $entries = @()
        $coverage = @()
        $signature = 'Unavailable'
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $target
            $signature = [string]$sig.Status
            if ($sig.SignerCertificate) { $signature += ' | ' + $sig.SignerCertificate.Subject }
        } catch { $signature = 'Unavailable: ' + $_.Exception.Message }
        foreach ($base in @('HKCU:', 'HKLM:')) {
            foreach ($kind in @('Run', 'RunOnce')) {
                $location = "$base\Software\Microsoft\Windows\CurrentVersion\$kind"
                try {
                    if (Test-Path -LiteralPath $location) {
                        $key = Get-Item -LiteralPath $location
                        foreach ($label in $key.GetValueNames()) {
                            if (DirectTarget ([string]$key.GetValue($label))) {
                                $entries += "$location | $label"
                            }
                        }
                    }
                } catch { $coverage += "$location unavailable" }
            }
        }
        try {
            foreach ($service in (Get-CimInstance Win32_Service)) {
                if (DirectTarget $service.PathName) { $entries += "Service | $($service.Name) | $($service.StartMode)" }
            }
        } catch { $coverage += 'Service inventory unavailable' }
        try {
            foreach ($task in (Get-ScheduledTask)) {
                foreach ($action in $task.Actions) {
                    if (DirectTarget $action.Execute) { $entries += "Task | $($task.TaskPath)$($task.TaskName)" }
                }
            }
        } catch { $coverage += 'Scheduled task inventory unavailable' }
        ConvertTo-Json -Compress -InputObject @{signature=$signature; entries=$entries; gaps=$coverage}
    }
    'disable-startup' {
        $entry = $env:DETECTOR_STARTUP_ENTRY
        $backupDir = Join-Path $env:LOCALAPPDATA 'CryptojackingDetector\startup-backups'
        [void](New-Item -ItemType Directory -Path $backupDir -Force)
        $backup = Join-Path $backupDir (([guid]::NewGuid().ToString()) + '.xml')
        if ($entry.StartsWith('Task | ')) {
            $full = $entry.Substring(7)
            $split = $full.LastIndexOf('\')
            if ($split -lt 0) { throw 'Invalid task entry' }
            $taskPath = $full.Substring(0, $split+1)
            $taskName = $full.Substring($split+1)
            $task = @(Get-ScheduledTask | Where-Object { $_.TaskName -eq $taskName -and $_.TaskPath -eq $taskPath })
            if ($task.Count -ne 1 -or $task[0].Actions.Count -ne 1 -or -not (DirectTarget $task[0].Actions[0].Execute)) { throw 'Task changed or has additional actions' }
            if ($task[0].State -eq 'Disabled') { throw 'Task already disabled' }
            Export-ScheduledTask -InputObject $task[0] | Out-File -LiteralPath $backup -Encoding Unicode
            Disable-ScheduledTask -InputObject $task[0] | Out-Null
        } elseif ($entry.StartsWith('Service | ')) {
            $parts = $entry -split ' \| ',3
            $service = @(Get-CimInstance Win32_Service | Where-Object { $_.Name -eq $parts[1] })
            if ($service.Count -ne 1 -or -not (DirectTarget $service[0].PathName)) { throw 'Service target changed' }
            if ($service[0].StartMode -eq 'Disabled') { throw 'Service already disabled' }
            $service[0] | Select-Object Name,PathName,StartMode,DelayedAutoStart | Export-Clixml -LiteralPath $backup
            $result = Invoke-CimMethod -InputObject $service[0] -MethodName ChangeStartMode -Arguments @{StartMode='Disabled'}
            if ($result.ReturnValue -ne 0) { throw "Windows rejected service change ($($result.ReturnValue))" }
        } else {
            $parts = $entry -split ' \| ',2
            if ($parts.Count -ne 2 -or $parts[0] -notmatch '^HK(CU|LM):\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(Once)?$') { throw 'Unknown startup entry' }
            $key = Get-Item -LiteralPath $parts[0]
            $name = $parts[1]
            $option = [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
            $value = $key.GetValue($name, $null, $option)
            if (-not (DirectTarget $value)) { throw 'Registry target changed' }
            $kind = $key.GetValueKind($name)
            @{Key=$parts[0];Name=$name;Value=$value;Kind=[string]$kind} | Export-Clixml -LiteralPath $backup
            $hive = if ($parts[0].StartsWith('HKCU:')) { [Microsoft.Win32.Registry]::CurrentUser } else { [Microsoft.Win32.Registry]::LocalMachine }
            $writable = $hive.OpenSubKey($parts[0].Substring(6), $true)
            if (-not $writable) { throw 'Cannot open registry key for writing' }
            try {
                if ($writable.GetValue($name,$null,$option) -cne $value) { throw 'Value changed during review' }
                $writable.DeleteValue($name, $true)
            } finally { $writable.Dispose() }
        }
        ConvertTo-Json -Compress -InputObject "Startup entry disabled. Backup: $backup"
    }
    'scan' {
        if (-not $target -or -not (Test-Path -LiteralPath $target -PathType Leaf)) { throw 'Selected file is unavailable.' }
        if ([System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($target)) { throw 'Use Windows Security to scan this path directly.' }
        $started = Get-Date
        Start-MpScan -ScanType CustomScan -ScanPath $target
        $labels = @{1='Detected';2='Cleaned';3='Quarantined';4='Removed';5='Allowed';6='Blocked'}
        try {
            $records = @(Get-MpThreatDetection | Where-Object {
                $hit = $_
                $exact = @($hit.Resources | Where-Object { $_ -ieq ('file:_' + $target) -or $_ -ieq $target }).Count -gt 0
                $exact -and ($hit.InitialDetectionTime -ge $started -or $hit.LastThreatStatusChangeTime -ge $started)
            })
            $states = @($records | ForEach-Object {
                $code = [int]$_.ThreatStatusID
                if ($_.ActionSuccess -and $code -in 2,3,4,6) { $labels[$code] }
                elseif ($code -in 1,5) { $labels[$code] }
                else { 'Review action status in Protection history' }
            } | Sort-Object -Unique)
            $result = if ($states.Count) { 'Defender recorded for this path: ' + ($states -join ', ') }
                      else { 'Scan finished. No new exact-path action was found. Review Protection history for details.' }
        } catch {
            $result = 'Scan finished. Detection history was unavailable. Open Protection history to check the action.'
        }
        ConvertTo-Json -Compress -InputObject $result
    }
}
