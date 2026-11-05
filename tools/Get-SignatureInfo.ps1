param(
    [Parameter(Mandatory = $true)][string]$PathsFile,
    [Parameter(Mandatory = $true)][string]$OutputFile
)

$ErrorActionPreference = 'Stop'
$results = New-Object System.Collections.ArrayList

$paths = @()
if (Test-Path -LiteralPath $PathsFile) {
    $paths = @(Get-Content -LiteralPath $PathsFile -Encoding UTF8 | Where-Object { $_ -and $_.Trim().Length -gt 0 })
}

foreach ($rawPath in $paths) {
    $path = $rawPath.Trim()
    $item = $null
    try {
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    } catch {
        [void]$results.Add([ordered]@{
            path = $path
            status = 'Missing'
            subject = ''
            issuer = ''
            thumbprint = ''
            not_before = ''
            not_after = ''
            size = $null
            modified = ''
            company = ''
            product = ''
            file_version = ''
            error = $_.Exception.Message
        })
        continue
    }

    $status = 'UnknownError'
    $subject = ''
    $issuer = ''
    $thumbprint = ''
    $notBefore = ''
    $notAfter = ''
    $errorText = ''
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $item.FullName -ErrorAction Stop
        $status = [string]$sig.Status
        if ($sig.SignerCertificate) {
            $subject = [string]$sig.SignerCertificate.Subject
            $issuer = [string]$sig.SignerCertificate.Issuer
            $thumbprint = [string]$sig.SignerCertificate.Thumbprint
            $notBefore = $sig.SignerCertificate.NotBefore.ToString('o')
            $notAfter = $sig.SignerCertificate.NotAfter.ToString('o')
        }
    } catch {
        $errorText = $_.Exception.Message
    }

    $company = ''
    $product = ''
    $fileVersion = ''
    try {
        $company = [string]$item.VersionInfo.CompanyName
        $product = [string]$item.VersionInfo.ProductName
        $fileVersion = [string]$item.VersionInfo.FileVersion
    } catch { }

    [void]$results.Add([ordered]@{
        path = $item.FullName
        status = $status
        subject = $subject
        issuer = $issuer
        thumbprint = $thumbprint
        not_before = $notBefore
        not_after = $notAfter
        size = [long]$item.Length
        modified = $item.LastWriteTimeUtc.ToString('o')
        company = $company
        product = $product
        file_version = $fileVersion
        error = $errorText
    })
}

$json = ConvertTo-Json -InputObject @($results) -Depth 5
if (-not $json) { $json = '[]' }
[System.IO.File]::WriteAllText($OutputFile, $json, (New-Object System.Text.UTF8Encoding($false)))
