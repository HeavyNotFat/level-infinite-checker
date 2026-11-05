param(
    [Parameter(Mandatory = $true)][string]$PathsFile,
    [Parameter(Mandatory = $true)][string]$OutputFile
)

$ErrorActionPreference = 'Continue'
$results = New-Object System.Collections.ArrayList
$paths = @()
if (Test-Path -LiteralPath $PathsFile) {
    $paths = @(Get-Content -LiteralPath $PathsFile -Encoding UTF8 | Where-Object { $_ -and $_.Trim().Length -gt 0 })
}
$shell = New-Object -ComObject WScript.Shell
foreach ($rawPath in $paths) {
    $path = $rawPath.Trim()
    $target = ''
    $arguments = ''
    $workingDirectory = ''
    $url = ''
    $errorText = ''
    try {
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($item.Extension -ieq '.lnk') {
            $shortcut = $shell.CreateShortcut($item.FullName)
            $target = [string]$shortcut.TargetPath
            $arguments = [string]$shortcut.Arguments
            $workingDirectory = [string]$shortcut.WorkingDirectory
        } elseif ($item.Extension -ieq '.url') {
            $content = Get-Content -LiteralPath $item.FullName -Raw -ErrorAction Stop
            if ($content -match '(?im)^URL=(.+)$') { $url = $Matches[1].Trim() }
        } else {
            $target = $item.FullName
        }
    } catch {
        $errorText = $_.Exception.Message
    }
    [void]$results.Add([ordered]@{
        path = $path
        target = $target
        arguments = $arguments
        working_directory = $workingDirectory
        url = $url
        error = $errorText
    })
}
$json = ConvertTo-Json -InputObject @($results) -Depth 5
if (-not $json) { $json = '[]' }
[System.IO.File]::WriteAllText($OutputFile, $json, (New-Object System.Text.UTF8Encoding($false)))
