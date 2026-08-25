param(
  [string]$ManifestPath = "",
  [switch]$Ask
)
# v1.25: 跨平台环境变量兜底
$envUser = if ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }
$envTmp  = if ($env:TEMP) { $env:TEMP } elseif ($env:TMP) { $env:TMP } else { [System.IO.Path]::GetTempPath() }


# ===================== 银狐木马隔离文件恢复工具 v1.7 =====================
# 用法:
#   双击 恢复隔离文件.bat (自动查找桌面最新隔离清单)
#   或  powershell -File Restore.ps1 -ManifestPath "路径\隔离清单.txt"
#   可选 -Ask 逐个确认

try { [Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(936) } catch {
  try { [System.Text.Encoding]::RegisterProvider([System.Text.CodePagesEncodingProvider]::Instance); [Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(936) } catch {}   # v1.42: pwsh7/.NET Core 需注册代码页
}

# v1.15: 日志写到工具目录(脚本所在目录的父目录=bat同目录), 用户目录作兜底
$script:toolRoot = Split-Path (Split-Path $PSCommandPath -Parent) -Parent
try { New-Item -ItemType Directory -Path $script:toolRoot -Force -ErrorAction Stop | Out-Null; $logDir = $script:toolRoot } catch { $logDir = $envUser }
$DebugLog = Join-Path $logDir "sf_restore_debug.log"
"" | Out-File -FilePath $DebugLog -Append -Encoding UTF8
Add-Content -Path $DebugLog -Value ("=== 恢复开始 $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') === Args=" + ($args -join ','))

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  银狐木马隔离文件恢复工具 v1.7"                            -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ---------- 1. 定位隔离清单 ----------
if (-not $ManifestPath) {
  # v1.7.1: 兼容 OneDrive 重定向桌面, 同时尝试多个桌面位置
  $desktops = @()
  try {
    $d = [Environment]::GetFolderPath('Desktop')
    if ($d) { $desktops += $d }
  } catch {}
  $desktops += @("$envUser\Desktop", "$envUser\OneDrive\Desktop", $env:USERPROFILE)
  # 也搜脚本当前目录(可能用户把工具放到隔离区里)
  $desktops += $PWD.Path

  foreach ($d in $desktops) {
    if (-not $d -or -not (Test-Path $d)) { continue }
    try {
      $cands = Get-ChildItem -Path $d -Filter '隔离清单.txt' -Recurse -Depth 3 -ErrorAction SilentlyContinue |
               Where-Object { $_.FullName -like '*银狐木马隔离区_*' } |
               Sort-Object LastWriteTime -Descending
      if ($cands) { $ManifestPath = $cands[0].FullName; break }
    } catch {}
  }
}

if (-not $ManifestPath -or -not (Test-Path $ManifestPath)) {
  Write-Host "  [错误] 找不到隔离清单.txt" -ForegroundColor Red
  Write-Host "  请把清单路径作为参数传入, 例如:" -ForegroundColor Yellow
  Write-Host '  powershell -ExecutionPolicy Bypass -File Restore.ps1 -ManifestPath "D:\xx\隔离清单.txt"' -ForegroundColor Yellow
  Write-Host ""
  Write-Host "按任意键关闭..."
  Read-Host | Out-Null
  return 1
}

Write-Host ("  [清单] " + $ManifestPath)
Write-Host ""

# ---------- 2. 解析清单 ----------
$lines = Get-Content -Path $ManifestPath -Encoding UTF8
$entries = @()
foreach ($line in $lines) {
  if (-not $line) { continue }
  # 格式: <隔离区完整路径> <= 原始路径: <原始路径>
  if ($line -notmatch '^(.*?)\s*<=\s*原始路径:\s*(.+)$') { continue }   # v1.42: 右侧贪婪, 状态/回滚字段提取时剥离
  $q = $Matches[1].Trim()
  $o = ($Matches[2] -replace '\s+\[[^\[\]]*\]\s*$', '' -replace '\s*\|\s*原隔离区:\s*.*$', '').Trim()   # v1.42: 剥尾部 [状态]/| 原隔离区 (含 [ 的路径安全)
  if ($q -and $o) { $entries += [PSCustomObject]@{ Quarantined=$q; Original=$o } }
}
if ($entries.Count -eq 0) {
  Write-Host "  [错误] 清单中没有可解析的条目" -ForegroundColor Red
  return 1
}
Write-Host ("  [清单] 共 " + $entries.Count + " 条记录")
Write-Host ""

# ---------- 3. 逐个恢复 ----------
$ok = 0; $skip = 0; $fail = 0
$failList = @()
foreach ($e in $entries) {
  $q = $e.Quarantined; $o = $e.Original
  $lineShow = Split-Path $o -Leaf
  if ($Ask) {
    Write-Host ("  恢复 " + $lineShow + " ?  (Y/N, 回车=Y)")
    $ans = Read-Host "  "
    if ($ans -and $ans.ToLower() -ne 'y') { $skip++; continue }
  }
  # a) 隔离区文件不存在
  if (-not (Test-Path $q)) {
    $skip++
    Write-Host ("  [跳过] 隔离区文件不存在: " + $q) -ForegroundColor DarkYellow
    Add-Content -Path $DebugLog -Value ("SKIP 不存在: $q")
    continue
  }
  # b) 原始路径已有同名文件 -> 不覆盖, 跳过
  if (Test-Path $o) {
    $skip++
    Write-Host ("  [跳过] 原始位置已有文件(为避免覆盖): " + $o) -ForegroundColor DarkYellow
    Add-Content -Path $DebugLog -Value ("SKIP 已存在: $o")
    continue
  }
  # c) 原始目录不存在 -> 尝试创建
  $odir = Split-Path $o -Parent
  if (-not (Test-Path $odir)) {
    try { New-Item -ItemType Directory -Path $odir -Force | Out-Null } catch {}
  }
  # d) 移动
  try {
    Move-Item -Path $q -Destination $o -Force -ErrorAction Stop
    $ok++
    Write-Host ("  [OK] " + $lineShow + "  <- 已恢复") -ForegroundColor Green
    Add-Content -Path $DebugLog -Value ("OK: $q -> $o")
  } catch {
    $fail++
    $failList += $o
    Write-Host ("  [失败] " + $lineShow + " : " + $_.Exception.Message) -ForegroundColor Red
    Add-Content -Path $DebugLog -Value ("FAIL: $q -> $o : " + $_.Exception.Message)
  }
}

# ---------- 4. 汇总 ----------
Write-Host ""
Write-Host "============================================================"
Write-Host ("  恢复完成: 成功 " + $ok + "  / 跳过 " + $skip + "  / 失败 " + $fail)
Write-Host "============================================================"
if ($fail -gt 0) {
  Write-Host ""
  Write-Host "  以下文件未能恢复(多为程序正在占用, 请先退出程序再重试):" -ForegroundColor Yellow
  $failList | ForEach-Object { Write-Host ("    - " + $_) }
  Write-Host ""
  Write-Host "  恢复失败的详细日志: " + $DebugLog
}
Write-Host ""
Write-Host "  提示: 成功恢复的程序, 重新启动即可正常使用。"
Write-Host "  隔离区目录若已清空可手动删除。"
Write-Host ""
Write-Host "按任意键关闭..."
Read-Host | Out-Null
return 0