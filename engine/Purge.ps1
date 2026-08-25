param(
  [string]$DirPath = "",
  [switch]$Recycle,
  [switch]$All,
  [switch]$NoBackup
)
# v1.25: 跨平台环境变量兜底
$envUser = if ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }
$envTmp  = if ($env:TEMP) { $env:TEMP } elseif ($env:TMP) { $env:TMP } else { [System.IO.Path]::GetTempPath() }


# ===================== 银狐木马隔离区清理工具 v1.9 (想法1 + 回滚) =====================
# 功能: 列出隔离区文件, 让用户选择删除(永久删除或进回收站), 写审计日志
# v1.9: 删除前自动备份到桌面 银狐回滚备份_* (可回滚), -NoBackup 跳过备份
# 用法:
#   双击 清理隔离区.bat
#   或 powershell -File Purge.ps1 -DirPath "路径\银狐木马隔离区_xxx"
#   可选: -Recycle 移到回收站(默认永久删除)  -All 全部删除  -NoBackup 不备份
# 审计: %logDir%\sf_purge_audit.log (工具目录)

try { [Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(936) } catch {
  try { [System.Text.Encoding]::RegisterProvider([System.Text.CodePagesEncodingProvider]::Instance); [Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(936) } catch {}   # v1.42: pwsh7/.NET Core 需注册代码页
}

# v1.15: 日志写到工具目录(脚本所在目录的父目录=bat同目录), 用户目录作兜底
$script:toolRoot = Split-Path (Split-Path $PSCommandPath -Parent) -Parent
try { New-Item -ItemType Directory -Path $script:toolRoot -Force -ErrorAction Stop | Out-Null; $logDir = $script:toolRoot } catch { $logDir = $envUser }
$AuditLog = Join-Path $logDir "sf_purge_audit.log"
"" | Out-File -FilePath $AuditLog -Append -Encoding UTF8
Add-Content -Path $AuditLog -Value ("=== 清理开始 $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  Args=" + ($args -join ','))

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  银狐木马隔离区清理工具 v1.8"                               -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ---------- 1. 定位隔离区目录 ----------
if (-not $DirPath) {
  $desktops = @()
  try { $d = [Environment]::GetFolderPath('Desktop'); if ($d) { $desktops += $d } } catch {}
  $desktops += @("$envUser\Desktop", "$envUser\OneDrive\Desktop", $envUser, $PWD.Path)
  foreach ($d in $desktops) {
    if (-not $d -or -not (Test-Path $d)) { continue }
    try {
      $cands = Get-ChildItem -Path $d -Directory -Filter '银狐木马隔离区_*' -ErrorAction SilentlyContinue |
               Sort-Object LastWriteTime -Descending
      if ($cands) { $DirPath = $cands[0].FullName; break }
    } catch {}
  }
}

if (-not $DirPath -or -not (Test-Path $DirPath)) {
  Write-Host "  [错误] 找不到隔离区目录" -ForegroundColor Red
  Write-Host '  请把隔离区目录路径作为参数传入: powershell -File Purge.ps1 -DirPath "D:\xx\银狐木马隔离区_xxx"' -ForegroundColor Yellow
  Write-Host ""
  Write-Host "按任意键关闭..."
  Read-Host | Out-Null
  return 1
}

Write-Host ("  [隔离区] " + $DirPath)
Write-Host ""

# ---------- 2. 列出文件 ----------
$files = Get-ChildItem -Path $DirPath -File -ErrorAction SilentlyContinue |
         Where-Object { $_.Name -ne '隔离清单.txt' } |
         Sort-Object Name
if (-not $files) {
  Write-Host "  [提示] 隔离区已没有文件(可能已恢复或已清理)" -ForegroundColor Green
  Write-Host "  隔离区目录可手动删除: $DirPath"
  Read-Host | Out-Null
  return 0
}

# 读取隔离清单映射: 隔离区文件名 -> 原始路径
$origMap = @{}
$manifestPath = Join-Path $DirPath '隔离清单.txt'
if (Test-Path $manifestPath) {
  foreach ($line in (Get-Content -Path $manifestPath -Encoding UTF8)) {
    if ($line -match '^(.*?)\s*<=\s*原始路径:\s*(.+)$') {   # v1.42: 右侧贪婪, 状态/回滚字段提取时剥离
      $qLeaf = Split-Path $Matches[1].Trim() -Leaf
      if ($qLeaf) { $origMap[$qLeaf] = ($Matches[2] -replace '\s+\[[^\[\]]*\]\s*$', '' -replace '\s*\|\s*原隔离区:\s*.*$', '').Trim() }   # v1.42: 剥尾部 [原因]/| 原隔离区
    }
  }
}

Write-Host ("  共 " + $files.Count + " 个文件:") -ForegroundColor Gray
Write-Host ""
$i = 0
foreach ($f in $files) {
  $i++
  $orig = $origMap[$f.Name]
  $sz = if ($f.Length -ge 1MB) { ("{0:N1} MB" -f ($f.Length/1MB)) } else { ("{0:N0} KB" -f ($f.Length/1KB)) }
  $origShow = if ($orig) { " <- " + $orig } else { "" }
  Write-Host ("  [{0,2}] {1,-40} ({2,8}){3}" -f $i, $f.Name, $sz, $origShow)
}
Write-Host ""

# ---------- 3. 选择 ----------
if ($All) {
  Write-Host "  [模式] -All 参数: 将处理全部文件" -ForegroundColor Yellow
  $selected = @($files | ForEach-Object { $_.Name })
} else {
  Write-Host "  请输入要删除的文件序号, 支持:"
  Write-Host "    单个:    1"
  Write-Host "    多个:    1,3,5"
  Write-Host "    范围:    1-3"
  Write-Host "    全部:    all"
  Write-Host "    取消:    0"
  Write-Host ""
  $sel = Read-Host "  选择"
  if (-not $sel -or $sel.Trim() -eq '0') {
    Write-Host "  已取消, 未删除任何文件。" -ForegroundColor Yellow
    Read-Host | Out-Null
    return 0
  }
  $sel = $sel.Trim().ToLower()
  $selected = @()
  if ($sel -eq 'all') {
    $selected = @($files | ForEach-Object { $_.Name })
  } else {
    # 解析 1,3,5 与 1-3
    foreach ($part in ($sel -split ',')) {
      $part = $part.Trim()
      if ($part -match '^(\d+)-(\d+)$') {
        $a = [int]$Matches[1]; $b = [int]$Matches[2]
        if ($a -gt $b) { $tmp = $a; $a = $b; $b = $tmp }
        for ($n = $a; $n -le $b; $n++) {
          if ($n -ge 1 -and $n -le $files.Count) { $selected += $files[$n-1].Name }
        }
      } elseif ($part -match '^\d+$') {
        $n = [int]$part
        if ($n -ge 1 -and $n -le $files.Count) { $selected += $files[$n-1].Name }
      }
    }
  }
  $selected = @($selected | Select-Object -Unique)
  if (-not $selected) {
    Write-Host "  输入无效, 未删除任何文件。" -ForegroundColor Yellow
    Read-Host | Out-Null
    return 0
  }
}

Write-Host ""
Write-Host ("  已选择 " + $selected.Count + " 个文件:") -ForegroundColor Gray
$selected | ForEach-Object { Write-Host ("    - " + $_) }

# ---------- 4. 二次确认 ----------
Write-Host ""
$mode = if ($Recycle) { "移到回收站" } else { "永久删除(不可恢复)" }
Write-Host ("  操作: " + $mode) -ForegroundColor Yellow
$ans = Read-Host ("  确认执行? 输入 DELETE 确认, 其他任意键取消")
if ($ans -ne 'DELETE') {
  Write-Host "  已取消, 未删除任何文件。" -ForegroundColor Yellow
  Read-Host | Out-Null
  return 0
}

# ---------- 5. 回滚备份准备 (v1.9) ----------
$rollbackDir = $null
$rollbackManifest = $null
# 永久删除时默认先备份到桌面 银狐回滚备份_*, 便于回滚; 回收站模式无需备份(回收站即后悔药)
if (-not $Recycle -and -not $NoBackup) {
  try { $desktop = [Environment]::GetFolderPath('Desktop') } catch { $desktop = $null }
  if (-not $desktop) { $desktop = $envUser }
  $rbStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
  $rollbackDir = Join-Path $desktop ("银狐回滚备份_" + $rbStamp)
  try { New-Item -ItemType Directory -Path $rollbackDir -Force | Out-Null } catch {}
  $rollbackManifest = Join-Path $rollbackDir '回滚清单.txt'
  "# 回滚清单 - 由清理工具自动生成 (删除前备份)" | Set-Content -Path $rollbackManifest -Encoding UTF8
  Add-Content -Path $rollbackManifest -Value ("# 生成时间: " + (Get-Date)) -Encoding UTF8
  Write-Host ("  [备份] 删除前将备份到: " + $rollbackDir) -ForegroundColor Yellow
  Add-Content -Path $AuditLog -Value ("[备份目录] $rollbackDir  (来自 $DirPath)") -Encoding UTF8
}

# ---------- 6. 执行 ----------
$ok = 0; $fail = 0; $failList = @()
if ($Recycle) {
  try { Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop } catch {}
}
foreach ($name in $selected) {
  $fp = Join-Path $DirPath $name
  if (-not (Test-Path $fp)) { $fail++; $failList += "$name (不存在)"; continue }
  $orig = $origMap[$name]
  try {
    # 先备份 (永久删除 + 未禁用备份时)
    $bkName = $name
    if ($rollbackDir) {
      $bkDest = Join-Path $rollbackDir $bkName
      $n = 1
      while (Test-Path $bkDest) {
        $n++
        $bkDest = Join-Path $rollbackDir ($bkName + "_" + $n)
      }
      Copy-Item -Path $fp -Destination $bkDest -Force -ErrorAction Stop
      # 写回滚清单: 备份文件名 | 原始路径 | 原隔离区路径
      $origPath = if ($orig) { $orig } else { '未知' }
      $bkLine = (Split-Path $bkDest -Leaf) + " <= 原始路径: " + $origPath + " | 原隔离区: " + $fp
      Add-Content -Path $rollbackManifest -Value $bkLine -Encoding UTF8
    }
    # 再删除
    if ($Recycle) {
      [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($fp,'OnlyErrorDialogs','SendToRecycleBin')
    } else {
      Remove-Item -Path $fp -Force -ErrorAction Stop
    }
    $ok++
    $bkNote = if ($rollbackDir) { ("  回滚备份: " + $bkDest) } else { "" }
    $origPath = if ($orig) { $orig } else { '未知' }
    $audit = ("[删除 {0}] 隔离区: {1}  原始路径: {2}  操作者: {3}{4}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $fp, $origPath, $env:USERNAME, $bkNote)
    Add-Content -Path $AuditLog -Value $audit -Encoding UTF8
    Write-Host ("  [OK] 已删除: " + $name) -ForegroundColor Green
  } catch {
    $fail++
    $failList += ($name + " : " + $_.Exception.Message)
    Write-Host ("  [失败] " + $name + " : " + $_.Exception.Message) -ForegroundColor Red
  }
}

# ---------- 7. 汇总 ----------
Write-Host ""
Write-Host "============================================================"
Write-Host ("  清理完成: 成功 " + $ok + "  / 失败 " + $fail)
Write-Host "============================================================"
if ($fail -gt 0) {
  Write-Host ""
  Write-Host "  失败明细:" -ForegroundColor Yellow
  $failList | ForEach-Object { Write-Host ("    - " + $_) }
}
Write-Host ""
if ($rollbackDir) {
  Write-Host ("  [回滚] 删除前已备份, 如需恢复运行: 回滚恢复.bat") -ForegroundColor Green
  Write-Host ("        备份目录: " + $rollbackDir)
}
Write-Host ("  审计日志: " + $AuditLog)
$remaining = @(Get-ChildItem -Path $DirPath -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne '隔离清单.txt' })
if (-not $remaining) {
  Write-Host "  隔离区已清空, 目录可手动删除: $DirPath" -ForegroundColor Green
}
Write-Host ""
Write-Host "按任意键关闭..."
Read-Host | Out-Null
return 0