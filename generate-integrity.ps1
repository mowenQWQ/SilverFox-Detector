# =====================================================================
# SilverFox Detector - integrity.manifest generator
# Uses the exact same salt & signature algorithm as
#   engine\SilverFoxDetect.ps1::Test-Integrity  and  main.go::runIntegrityCheck
#
# Purpose: after modifying any tool file (e.g. engine/SilverFoxDetect.ps1),
#   rerun this against the publish package's legacy/ dir so the integrity
#   self-check stops reporting "tampered".
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File generate-integrity.ps1 -LegacyDir <path>
#   Defaults to a sibling "legacy" dir when -LegacyDir is omitted.
# =====================================================================
param([string]$LegacyDir)

$salt = 'SilverFoxDetector-INTEGRITY-SALT-v1-!@#$%^&*2026'   # same salt as engine/main
if (-not $LegacyDir) { $LegacyDir = Join-Path $PSScriptRoot 'legacy' }
$LegacyDir = $LegacyDir.TrimEnd('\', '/')
if (-not (Test-Path -LiteralPath $LegacyDir)) {
  Write-Output ("[ERR] legacy dir not found: " + $LegacyDir); exit 1
}

$sep = [IO.Path]::DirectorySeparatorChar
# Enumerate all files under legacy (excluding the manifest itself), sort for determinism
$files = @(Get-ChildItem -LiteralPath $LegacyDir -Recurse -File -ErrorAction SilentlyContinue |
           Where-Object { $_.Name -ne 'integrity.manifest' } |
           Sort-Object FullName)

$sha     = [System.Security.Cryptography.SHA256]::Create()
$rootLen = $LegacyDir.Length + 1
$entries = New-Object System.Collections.Generic.List[string]
foreach ($f in $files) {
  $rel = $f.FullName.Substring($rootLen) -replace [regex]::Escape($sep), '/'   # relative path, '/'-separated
  $h   = ([System.BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($f.FullName))) -replace '-', '').ToLower()
  $entries.Add($rel + '|' + $h)
}
if ($entries.Count -eq 0) { Write-Output "[ERR] legacy dir is empty, nothing to sign"; exit 1 }

$signed  = 'signed=' + (Get-Date -Format 'yyyy-MM-dd')
# Signature payload = entry lines (join "\n") + "\n" + full "signed=" line + salt (identical to both verifiers)
$payload = ($entries -join "`n") + "`n" + $signed + $salt
$sig     = ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($payload))) -replace '-', '').ToLower().Substring(0, 16)

$content = ($entries -join "`n") + "`n" + $signed + "`n" + 'sig=' + $sig
$mf = Join-Path $LegacyDir 'integrity.manifest'
# UTF-8 WITHOUT BOM (main.go reads raw bytes via os.ReadFile; a BOM would corrupt the first entry path)
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$sw = New-Object System.IO.StreamWriter($mf, $false, $utf8NoBom)
$sw.Write($content); $sw.Close()

Write-Output ("[OK] integrity.manifest regenerated at: " + $mf)
Write-Output ("  protected files=" + $entries.Count + "  signed=" + $signed + "  sig=" + $sig)