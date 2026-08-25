param(
  [string]$DirPath = "",
  [switch]$All
)
# v1.25: 跨平台环境变量兜底
$envUser = if ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }
$envTmp  = if ($env:TEMP) { $env:TEMP } elseif ($env:TMP) { $env:TMP } else { [System.IO.Path]::GetTempPath() }


# ===================== 银狐木马回滚恢复工具 v1.9 (想法9) =====================
# 功能: 从"银狐回滚备份_*"目录恢复被清理工具永久删除的文件
# 用法:
#   双击 回滚恢复.bat
#   或 powershell -File Rollback.ps1 -DirPath "路径\银狐回滚备份_xxx"
#   可选: -All 跳过选择直接全部恢复
# 审计: %logDir%\sf_purge_audit.log (工具目录)

try { [Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(936) } catch {
  try { [System.Text.Encoding]::RegisterProvider([System.Text.CodePagesEncodingProvider]::Instance); [Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(936) } catch {}   # v1.42: pwsh7/.NET Core 需注册代码页
}

# v1.15: 日志写到工具目录(脚本所在目录的父目录=bat同目录), 用户目录作兜底
$script:toolRoot = Split-Path (Split-Path $PSCommandPath -Parent) -Parent
try { New-Item -ItemType Directory -Path $script:toolRoot -Force -ErrorAction Stop | Out-Null; $logDir = $script:toolRoot } catch { $logDir = $envUser }
$AuditLog = Join-Path $logDir "sf_purge_audit.log"
"" | Out-File -FilePath $AuditLog -Append -Encoding UTF8
Add-Content -Path $AuditLog -Value ("=== 回滚开始 $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  Args=" + ($args -join ','))

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  银狐木马回滚恢复工具 v1.9"                                  -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ---------- 1. 定位回滚备份目录 ----------
if (-not $DirPath) {
  $desktops = @()
  try { $d = [Environment]::GetFolderPath('Desktop'); if ($d) { $desktops += $d } } catch {}
  $desktops += @("$envUser\Desktop", "$envUser\OneDrive\Desktop", $envUser, $PWD.Path)
  foreach ($d in $desktops) {
    if (-not $d -or -not (Test-Path $d)) { continue }
    try {
      $cands = Get-ChildItem -Path $d -Directory -Filter '银狐回滚备份_*' -ErrorAction SilentlyContinue |
               Sort-Object LastWriteTime -Descending
      if ($cands) { $DirPath = $cands[0].FullName; break }
    } catch {}
  }
}

if (-not $DirPath -or -not (Test-Path $DirPath)) {
  Write-Host "  [错误] 找不到回滚备份目录" -ForegroundColor Red
  Write-Host '  请把备份目录路径作为参数传入: powershell -File Rollback.ps1 -DirPath "D:\xx\银狐回滚备份_xxx"' -ForegroundColor Yellow
  Write-Host ""
  Write-Host "按任意键关闭..."
  Read-Host | Out-Null
  return 1
}

Write-Host ("  [备份目录] " + $DirPath)
Write-Host ""

# ---------- 2. 列出文件 ----------
$files = Get-ChildItem -Path $DirPath -File -ErrorAction SilentlyContinue |
         Where-Object { $_.Name -ne '回滚清单.txt' } |
         Sort-Object Name
if (-not $files) {
  Write-Host "  [提示] 备份目录已没有文件" -ForegroundColor Green
  Read-Host | Out-Null
  return 0
}

# 读取回滚清单: 备份文件名 <= 原始路径: xxx | 原隔离区: xxx
$origMap = @{}
$manifestPath = Join-Path $DirPath '回滚清单.txt'
if (Test-Path $manifestPath) {
  foreach ($line in (Get-Content -Path $manifestPath -Encoding UTF8)) {
    if ($line -match '^(.*?)\s*<=\s*原始路径:\s*(.+)$') {   # v1.42: 右侧贪婪, 状态/回滚字段提取时剥离
      $origMap[$Matches[1].Trim()] = ($Matches[2] -replace '\s+\[[^\[\]]*\]\s*$', '' -replace '\s*\|\s*原隔离区:\s*.*$', '').Trim()   # v1.42: 剥尾部 [原因]/| 原隔离区
    }
  }
}

Write-Host ("  共 " + $files.Count + " 个备份文件:") -ForegroundColor Gray
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
  Write-Host "  [模式] -All 参数: 将恢复全部文件" -ForegroundColor Yellow
  $selected = @($files | ForEach-Object { $_.Name })
} else {
  Write-Host "  请输入要恢复的文件序号, 支持:"
  Write-Host "    单个:    1"
  Write-Host "    多个:    1,3,5"
  Write-Host "    范围:    1-3"
  Write-Host "    全部:    all"
  Write-Host "    取消:    0"
  Write-Host ""
  $sel = Read-Host "  选择"
  if (-not $sel -or $sel.Trim() -eq '0') {
    Write-Host "  已取消, 未恢复任何文件。" -ForegroundColor Yellow
    Read-Host | Out-Null
    return 0
  }
  $sel = $sel.Trim().ToLower()
  $selected = @()
  if ($sel -eq 'all') {
    $selected = @($files | ForEach-Object { $_.Name })
  } else {
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
    Write-Host "  输入无效, 未恢复任何文件。" -ForegroundColor Yellow
    Read-Host | Out-Null
    return 0
  }
}

Write-Host ""
Write-Host ("  已选择 " + $selected.Count + " 个文件:") -ForegroundColor Gray
$selected | ForEach-Object { Write-Host ("    - " + $_) }

# ---------- 4. 确认 ----------
Write-Host ""
$ans = Read-Host "  将恢复到原始路径, 输入 RESTORE 确认, 其他任意键取消"
if ($ans -ne 'RESTORE') {
  Write-Host "  已取消, 未恢复任何文件。" -ForegroundColor Yellow
  Read-Host | Out-Null
  return 0
}

# ---------- 5. 执行恢复 ----------
$ok = 0; $fail = 0; $failList = @()
foreach ($name in $selected) {
  $bk = Join-Path $DirPath $name
  if (-not (Test-Path $bk)) { $fail++; $failList += "$name (备份不存在)"; continue }
  $orig = $origMap[$name]
  if (-not $orig -or $orig -eq '未知') {
    $fail++
    $failList += ("$name (清单中无原始路径, 无法自动恢复, 请手动处理)")
    Write-Host ("  [失败] " + $name + " : 清单中无原始路径") -ForegroundColor Red
    continue
  }
  try {
    # 原始目录不存在则创建
    $odir = Split-Path $orig -Parent
    if (-not (Test-Path $odir)) { New-Item -ItemType Directory -Path $odir -Force | Out-Null }
    # 原路径已有文件 -> 不覆盖, 跳过
    if (Test-Path $orig) {
      $fail++
      $failList += ("$name (原始路径已有文件: $orig)")
      Write-Host ("  [跳过] " + $name + " : 原始路径已有文件, 未覆盖") -ForegroundColor DarkYellow
      continue
    }
    Copy-Item -Path $bk -Destination $orig -Force -ErrorAction Stop
    Remove-Item -Path $bk -Force -ErrorAction Stop
    $ok++
    $audit = ("[回滚 {0}] 备份: {1}  恢复到: {2}  操作者: {3}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $bk, $orig, $env:USERNAME)
    Add-Content -Path $AuditLog -Value $audit -Encoding UTF8
    Write-Host ("  [OK] 已恢复: " + $name + " -> " + $orig) -ForegroundColor Green
  } catch {
    $fail++
    $failList += ($name + " : " + $_.Exception.Message)
    Write-Host ("  [失败] " + $name + " : " + $_.Exception.Message) -ForegroundColor Red
  }
}

# ---------- 6. 汇总 ----------
Write-Host ""
Write-Host "============================================================"
Write-Host ("  回滚完成: 成功 " + $ok + "  / 跳过失败 " + $fail)
Write-Host "============================================================"
if ($fail -gt 0) {
  Write-Host ""
  Write-Host "  失败明细:" -ForegroundColor Yellow
  $failList | ForEach-Object { Write-Host ("    - " + $_) }
}
Write-Host ""
Write-Host ("  审计日志: " + $AuditLog)
$remaining = @(Get-ChildItem -Path $DirPath -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne '回滚清单.txt' })
if (-not $remaining) {
  Write-Host "  备份目录已空, 可手动删除: $DirPath" -ForegroundColor Green
}
Write-Host ""
Write-Host "按任意键关闭..."
Read-Host | Out-Null
return 0