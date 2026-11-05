param(
    [Parameter(Mandatory = $false)][int]$MaxEvents = 3000,
    [Parameter(Mandatory = $false)][string]$OutputFile = ''
)

$ErrorActionPreference = 'Continue'
$errors = New-Object System.Collections.ArrayList
$result = [ordered]@{
    generated_at = (Get-Date).ToString('o')
    dns_cache = @()
    dns_events = @()
    sysmon_dns = @()
    available = [ordered]@{ dns_cache = $false; dns_events = $false; sysmon = $false }
    errors = @()
}

function Get-EventDataMap {
    param($Event)
    $map = @{}
    try {
        $xml = [xml]$Event.ToXml()
        foreach ($d in @($xml.Event.EventData.Data)) {
            if ($d.Name) { $map[[string]$d.Name] = [string]$d.'#text' }
        }
    } catch { }
    return $map
}

# ---------- DNS client cache (all domains the machine resolved recently) ----------
try {
    $cache = @(Get-DnsClientCache -ErrorAction Stop)
    $rows = New-Object System.Collections.ArrayList
    foreach ($item in $cache) {
        $name = [string]$item.Name
        if (-not $name) { continue }
        [void]$rows.Add([ordered]@{
            name = $name
            data = [string]$item.Data
            type = [string]$item.Type
            ttl  = [int64]$item.TimeToLive
        })
        if ($rows.Count -ge 20000) { break }
    }
    $result.dns_cache = @($rows)
    $result.available.dns_cache = $true
} catch {
    [void]$errors.Add('dns_cache: ' + $_.Exception.Message)
}

# ---------- DNS Client operational log (if enabled) ----------
try {
    $events = @(Get-WinEvent -LogName 'Microsoft-Windows-DNS-Client/Operational' -MaxEvents $MaxEvents -ErrorAction Stop)
    $rows = New-Object System.Collections.ArrayList
    foreach ($event in $events) {
        $data = Get-EventDataMap $event
        $query = [string]$data['QueryName']
        if (-not $query) { $query = [string]$data['Query'] }
        if (-not $query) { continue }
        [void]$rows.Add([ordered]@{
            time  = $event.TimeCreated.ToString('o')
            query = $query
            id    = [int]$event.Id
        })
        if ($rows.Count -ge $MaxEvents) { break }
    }
    $result.dns_events = @($rows)
    $result.available.dns_events = $true
} catch {
    [void]$errors.Add('dns_events: ' + $_.Exception.Message)
}

# ---------- Sysmon DNS query events (per-process domain requests) ----------
try {
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 22 } -MaxEvents $MaxEvents -ErrorAction Stop)
    $rows = New-Object System.Collections.ArrayList
    foreach ($event in $events) {
        $data = Get-EventDataMap $event
        $query = [string]$data['QueryName']
        if (-not $query) { continue }
        [void]$rows.Add([ordered]@{
            time  = $event.TimeCreated.ToString('o')
            query = $query
            image = [string]$data['Image']
            pid   = [string]$data['ProcessId']
        })
        if ($rows.Count -ge $MaxEvents) { break }
    }
    $result.sysmon_dns = @($rows)
    $result.available.sysmon = $true
} catch {
    [void]$errors.Add('sysmon: ' + $_.Exception.Message)
}

$result.errors = @($errors)
$json = ConvertTo-Json -InputObject $result -Depth 8 -Compress
if (-not $json) { $json = '{}' }
if (-not $OutputFile) {
    $OutputFile = Join-Path $env:TEMP ('vcheck-domains-' + [guid]::NewGuid().ToString('N') + '.json')
}
[System.IO.File]::WriteAllText($OutputFile, $json, (New-Object System.Text.UTF8Encoding($false)))
