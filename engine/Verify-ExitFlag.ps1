# Verify-ExitFlag.ps1 v1.13
# 验证 %TEMP%\sf_exit_<pid>_<nonce>.flag 是否为本工具产生的受控退出标记
# 用法: powershell -File Verify-ExitFlag.ps1
# 输出到 stdout, exit code: 0=有效受控退出 2=无标记 3=空 4=签名不符 5=JSON错

$Salt = 'SilverFoxDetector-v1.13-EXIT-SALT-!@#$%^&*'  # 与主引擎一致

$envTmp = if ($env:TEMP) { $env:TEMP } elseif ($env:TMP) { $env:TMP } else { [System.IO.Path]::GetTempPath() }
$f = Get-ChildItem (Join-Path $envTmp 'sf_exit_*.flag') -ErrorAction SilentlyContinue |
     Sort-Object LastWriteTime -Descending |
     Select-Object -First 1
if (-not $f) { Write-Output 'NO_FLAG'; exit 2 }
# v1.13+ 时间窗: 只验 5 分钟内的标记 (与引擎清理窗口一致), 防残留旧标记误判
if ((Get-Date) - $f.LastWriteTime -gt (New-TimeSpan -Minutes 5)) {
  Write-Output 'STALE_FLAG'; exit 2
}
$content = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
if (-not $content -or $content.Trim().Length -eq 0) { Write-Output 'EMPTY'; exit 3 }
$token = $content.Trim()
$pipeIdx = $token.LastIndexOf('|h=')
if ($pipeIdx -lt 0) { Write-Output 'BAD_FORMAT'; exit 4 }
$plain = $token.Substring(0, $pipeIdx)
$given = $token.Substring($pipeIdx + 3)

# 用 .NET SHA256 重算签名 (零 PS 操作符, 兼容 PS 5.1)
$sha = [System.Security.Cryptography.SHA256]::Create()
$bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($plain + $Salt))
$expected = ([System.BitConverter]::ToString($bytes) -replace '-', '').ToLower().Substring(0, 16)
if ($given -ne $expected) {
  Write-Output ('BAD_SIG given=' + $given + ' expected=' + $expected)
  exit 4
}

# 解析 JSON
try {
  $obj = $plain | ConvertFrom-Json -ErrorAction Stop
  if ($obj.ver -ne '1.13') {
    Write-Output ('BAD_VERSION ver=' + $obj.ver)
    exit 4
  }
  Write-Output ('OK PID=' + $obj.pid + ' CODE=' + $obj.code + ' REASON=' + $obj.reason + ' TIME=' + $obj.time)
  exit 0
} catch {
  Write-Output ('JSON_FAIL ' + $_.Exception.Message)
  exit 5
}