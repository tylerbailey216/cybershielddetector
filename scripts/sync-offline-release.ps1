param(
    [string]$DestinationRoot = "F:\Digital Awareness & Literacy Magazine"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$sourceRoot = Join-Path $projectRoot "public"
$resolvedDestination = [System.IO.Path]::GetFullPath($DestinationRoot)
$offlineRoot = [System.IO.Path]::GetFullPath((Join-Path $resolvedDestination "Offline Learning Hub"))

if (-not $offlineRoot.StartsWith($resolvedDestination, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Offline destination is outside the requested release root."
}

New-Item -ItemType Directory -Path $offlineRoot -Force | Out-Null

$files = @(
    "index.html",
    "styles.css",
    "gateway.js",
    "digital-literacy-gateway.png",
    "cover-schedule.js",
    "learning.js",
    "publication-reader.js",
    "learning.html",
    "cybershieldlogo.png",
    "release.json"
)

foreach ($relativePath in $files) {
    Copy-Item -LiteralPath (Join-Path $sourceRoot $relativePath) -Destination (Join-Path $offlineRoot $relativePath) -Force
}

$directories = @("fonts", "monthly-covers", "course-pages", "downloads")
foreach ($directory in $directories) {
    $sourceDirectory = Join-Path $sourceRoot $directory
    Get-ChildItem -LiteralPath $sourceDirectory -Recurse -File | ForEach-Object {
        $relativePath = $_.FullName.Substring($sourceDirectory.Length).TrimStart('\')
        $destinationPath = Join-Path (Join-Path $offlineRoot $directory) $relativePath
        New-Item -ItemType Directory -Path (Split-Path -Parent $destinationPath) -Force | Out-Null
        Copy-Item -LiteralPath $_.FullName -Destination $destinationPath -Force
    }
}

Copy-Item -LiteralPath (Join-Path $projectRoot "offline-launcher\README.txt") -Destination (Join-Path $offlineRoot "README.txt") -Force

$release = Get-Content -Raw -LiteralPath (Join-Path $sourceRoot "release.json") | ConvertFrom-Json
Write-Output "Offline release synchronized: $($release.release)"
Write-Output "Destination: $offlineRoot"
