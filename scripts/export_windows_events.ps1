<#
Export Security and Sysmon events (and the firewall log) for the Mini SOC.
Run in an ADMINISTRATOR PowerShell on the Windows VM:
  powershell -ExecutionPolicy Bypass -File export_windows_events.ps1 -OutDir E:\ -Minutes 120
#>
param(
    [int]$Minutes = 120,
    [string]$OutDir = "$env:USERPROFILE\Desktop"
)

$since = (Get-Date).AddMinutes(-$Minutes)
$queries = @(
    @{ LogName = 'Security'; Id = 4624, 4625, 4634, 4672, 4688, 4720 },
    @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1, 3 }
)
$skipUsers = '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|DWM-\d+|UMFD-\d+|.*\$)$'

$lines = New-Object System.Collections.Generic.List[string]
foreach ($q in $queries) {
    $q.StartTime = $since
    $events = Get-WinEvent -FilterHashtable $q -ErrorAction SilentlyContinue
    foreach ($e in $events) {
        $data = @{}
        foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) {
            if ($n.Name) { $data[$n.Name] = [string]$n.'#text' }
        }
        $user = $data['TargetUserName']
        if (-not $user) { $user = $data['SubjectUserName'] }
        if ($e.LogName -eq 'Security' -and $user -match $skipUsers) { continue }

        $rec = [ordered]@{
            TimeCreated = $e.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            EventID     = [int]$e.Id
            Channel     = $e.LogName
            Computer    = $e.MachineName
        }
        $fields = @{
            TargetUserName  = $user
            IpAddress       = $data['IpAddress']
            Image           = $data['Image']
            NewProcessName  = $data['NewProcessName']
            CommandLine     = $data['CommandLine']
            User            = $data['User']
            SourceIp        = $data['SourceIp']
            DestinationIp   = $data['DestinationIp']
            DestinationPort = $data['DestinationPort']
        }
        foreach ($k in $fields.Keys) { if ($fields[$k]) { $rec[$k] = $fields[$k] } }
        $lines.Add(($rec | ConvertTo-Json -Compress))
    }
}

$out = Join-Path $OutDir "windows_events.jsonl"
[System.IO.File]::WriteAllLines($out, $lines.ToArray())   # UTF-8 without BOM
Write-Host "Exported $($lines.Count) events to $out"

$fw = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
if (Test-Path $fw) {
    $fwOut = Join-Path $OutDir "pfirewall.log"
    [System.IO.File]::WriteAllLines($fwOut, [string[]](Get-Content $fw))
    Write-Host "Copied firewall log to $fwOut"
} else {
    Write-Host "No firewall log found yet. Enable firewall logging first."
}
