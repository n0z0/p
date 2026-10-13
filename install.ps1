# PowerShell One-Line Installer & Updater for `p` (Windows)
$ErrorActionPreference = 'Stop'

Write-Host "==> Mengunduh dan memasang 'p' versi terbaru..." -ForegroundColor Cyan

$repo = "n0z0/p"
$apiUrl = "https://api.github.com/repos/$repo/releases/latest"

try {
    $release = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "PowerShell" }
} catch {
    Write-Error "Gagal menghubungi GitHub API untuk mengambil rilis terbaru: $_"
    exit 1
}

$version = $release.tag_name
Write-Host "[+] Versi terbaru ditemukan: $version" -ForegroundColor Green

# Cari asset Windows zip
$asset = $release.assets | Where-Object { $_.name -like "*windows-msvc.zip" } | Select-Object -First 1
if (-not $asset) {
    Write-Error "Asset rilis Windows tidak ditemukan di versi $version"
    exit 1
}

$downloadUrl = $asset.browser_download_url
$tempZip = Join-Path $env:TEMP "p-windows.zip"
$tempExtract = Join-Path $env:TEMP "p-extract"

Write-Host "[+] Mengunduh $($asset.name)..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $downloadUrl -OutFile $tempZip -UseBasicParsing

Write-Host "[+] Mengekstrak berkas..." -ForegroundColor Cyan
if (Test-Path $tempExtract) {
    Remove-Item -Recurse -Force $tempExtract
}
Expand-Archive -Path $tempZip -DestinationPath $tempExtract -Force

$binFile = Get-ChildItem -Path $tempExtract -Recurse -Filter "p.exe" | Select-Object -First 1
if (-not $binFile) {
    Write-Error "File p.exe tidak ditemukan di dalam paket rilis!"
    exit 1
}

# Direktori instalasi di user profile: ~/.p/bin
$installDir = Join-Path $env:USERPROFILE ".p\bin"
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}

$destPath = Join-Path $installDir "p.exe"
Copy-Item -Path $binFile.FullName -Destination $destPath -Force

# Bersihkan temp
Remove-Item -Force $tempZip -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $tempExtract -ErrorAction SilentlyContinue

# Tambahkan ke User PATH jika belum ada
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$pathParts = @()
if ($userPath) {
    $pathParts = $userPath.Split(';') | Where-Object { $_ -ne '' }
}

if ($pathParts -notcontains $installDir) {
    Write-Host "[+] Menambahkan '$installDir' ke User PATH Environment..." -ForegroundColor Yellow
    $newPath = ($pathParts + $installDir) -join ';'
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
}

$env:Path = $installDir + ";" + $env:Path

Write-Host "[OK] 'p' ($version) berhasil dipasang/diperbarui di: $destPath" -ForegroundColor Green
Write-Host "[*] Anda dapat langsung menjalankan perintah 'p' di terminal!" -ForegroundColor Cyan
