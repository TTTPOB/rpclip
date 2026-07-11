[CmdletBinding()]
param(
    [string]$Version,
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Programs\RpClip\bin"),
    [switch]$NoPathUpdate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$repository = "tttpob/rpclip"
$headers = @{
    Accept = "application/vnd.github+json"
    "User-Agent" = "rpclip-windows-installer"
}
$assets = @(
    @{ ReleaseName = "rpclip-server-windows.exe"; InstallName = "rpclip-server.exe" },
    @{ ReleaseName = "rpclip-client-windows.exe"; InstallName = "rpclip-client.exe" }
)

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    throw "InstallDir cannot be empty"
}

if ([string]::IsNullOrWhiteSpace($Version)) {
    $releaseUri = "https://api.github.com/repos/$repository/releases/latest"
} else {
    if (-not $Version.StartsWith("v")) {
        $Version = "v$Version"
    }
    $encodedVersion = [Uri]::EscapeDataString($Version)
    $releaseUri = "https://api.github.com/repos/$repository/releases/tags/$encodedVersion"
}

Write-Host "Resolving RpClip release..."
$release = Invoke-RestMethod -Uri $releaseUri -Headers $headers
if ([string]::IsNullOrWhiteSpace([string]$release.tag_name)) {
    throw "GitHub returned a release without a tag"
}

$downloads = foreach ($assetSpec in $assets) {
    $matches = @($release.assets | Where-Object { $_.name -eq $assetSpec.ReleaseName })
    if ($matches.Count -ne 1) {
        throw "Release $($release.tag_name) does not contain $($assetSpec.ReleaseName)"
    }
    [PSCustomObject]@{
        Uri = $matches[0].browser_download_url
        ReleaseName = $assetSpec.ReleaseName
        InstallName = $assetSpec.InstallName
    }
}

$tempDir = Join-Path ([IO.Path]::GetTempPath()) ("rpclip-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempDir | Out-Null

try {
    foreach ($download in $downloads) {
        $destination = Join-Path $tempDir $download.InstallName
        Write-Host "Downloading $($download.ReleaseName)..."
        Invoke-WebRequest -Uri $download.Uri -OutFile $destination -Headers $headers -UseBasicParsing

        $stream = [IO.File]::OpenRead($destination)
        try {
            $first = $stream.ReadByte()
            $second = $stream.ReadByte()
        } finally {
            $stream.Dispose()
        }
        if ($first -ne 0x4D -or $second -ne 0x5A) {
            throw "Downloaded file $($download.ReleaseName) is not a Windows executable"
        }
    }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    foreach ($download in $downloads) {
        Move-Item -Path (Join-Path $tempDir $download.InstallName) `
            -Destination (Join-Path $InstallDir $download.InstallName) -Force
    }
} finally {
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}

if (-not $NoPathUpdate) {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $pathEntries = @($userPath -split ";" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $normalizedInstallDir = $InstallDir.TrimEnd("\")
    $alreadyPresent = $pathEntries | Where-Object {
        $_.Trim().TrimEnd("\").Equals($normalizedInstallDir, [StringComparison]::OrdinalIgnoreCase)
    }
    if (-not $alreadyPresent) {
        $newUserPath = (@($pathEntries) + $InstallDir) -join ";"
        [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
        Write-Host "Added $InstallDir to the user PATH."
    }

    $currentEntries = @($env:Path -split ";")
    $inCurrentSession = $currentEntries | Where-Object {
        $_.Trim().TrimEnd("\").Equals($normalizedInstallDir, [StringComparison]::OrdinalIgnoreCase)
    }
    if (-not $inCurrentSession) {
        $env:Path = "$env:Path;$InstallDir"
    }
}

Write-Host "Installed RpClip $($release.tag_name) to $InstallDir"
Write-Host "Server: rpclip-server.exe"
Write-Host "Client: rpclip-client.exe"
