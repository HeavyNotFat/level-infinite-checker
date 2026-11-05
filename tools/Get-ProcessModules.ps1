param(
    [Parameter(Mandatory = $false)][string[]]$Names = @('steam', 'steamwebhelper', 'steamservice', 'chrome', 'msedge', 'brave', 'vivaldi', 'opera', 'opera_gx', 'firefox', 'tbs_browser', 'nikke_launcher', 'nikke_launcher_hmt', 'nikke_launcher_google', 'spotify', 'chatgpt', 'eadesktop', 'nvcontainer'),
    [Parameter(Mandatory = $false)][string]$OutputFile = ''
)

$ErrorActionPreference = 'Continue'
$errors = New-Object System.Collections.ArrayList
$modules = New-Object System.Collections.ArrayList

# With -File, PowerShell can pass 'a,b' as one string; accept both forms.
if ($Names.Count -eq 1 -and $Names[0] -like '*,*') {
    $Names = @($Names[0] -split ',' | Where-Object { $_ })
}

foreach ($name in $Names) {
    try {
        $processes = @(Get-Process -Name $name -ErrorAction SilentlyContinue)
    } catch {
        [void]$errors.Add([ordered]@{ context = $name; message = $_.Exception.Message })
        continue
    }
    foreach ($p in $processes) {
        try {
            foreach ($m in @($p.Modules)) {
                [void]$modules.Add([ordered]@{
                    process = $p.ProcessName
                    pid = [int]$p.Id
                    module = [string]$m.ModuleName
                    path = [string]$m.FileName
                    size = [long]$m.ModuleMemorySize
                })
            }
        } catch {
            [void]$errors.Add([ordered]@{ context = ($name + ' pid=' + $p.Id); message = $_.Exception.Message })
        }
    }
}

$result = [ordered]@{
    generated_at = (Get-Date).ToString('o')
    modules = @($modules)
    errors = @($errors)
}
$json = ConvertTo-Json -InputObject $result -Depth 6 -Compress
if (-not $json) { $json = '{}' }
if (-not $OutputFile) { $OutputFile = Join-Path $env:TEMP ('vcheck-modules-' + [guid]::NewGuid().ToString('N') + '.json') }
[System.IO.File]::WriteAllText($OutputFile, $json, (New-Object System.Text.UTF8Encoding($false)))
