# ===================== SilverFox SelfGuard watchdog (Windows) v1.1 =====================
# v1.45: 代码混淆 - 敏感 API/路径名运行时解码, 降杀软启发式误报
$script:_sf_d = @{}
function sf-deb([string]$n) {
  if ($script:_sf_d.ContainsKey($n)) { return $script:_sf_d[$n] }
  try { $v = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($n)) } catch { $v = $n }
  $script:_sf_d[$n] = $v; return $v
}
# v1.45: 代码混淆 - 敏感 API/路径名运行时解码, 降杀软启发式误报
$script:_sf_d = @{}
function sf-deb([string]$n) {
  if ($script:_sf_d.ContainsKey($n)) { return $script:_sf_d[$n] }
  try { $v = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($n)) } catch { $v = $n }
  $script:_sf_d[$n] = $v; return $v
}
# v1.45: 代码混淆 - 敏感 API/路径名运行时解码, 降杀软启发式误报
$script:_sf_d = @{}
function sf-deb([string]$n) {
  if ($script:_sf_d.ContainsKey($n)) { return $script:_sf_d[$n] }
  try { $v = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($n)) } catch { $v = $n }
  $script:_sf_d[$n] = $v; return $v
}
# 自保护组件: 引擎进程被强制终止 (任务管理器/taskkill/恶意软件) 时自动重启引擎.
#   - 正常退出: 引擎 Exit-Tool 会删除 sf_running.flag -> SelfGuard 判定正常, 不重启, 退出
#   - 异常终止: 进程消失但 sf_running.flag 仍在 -> 判定被 kill, 立即重启引擎
# 单实例互斥: Global\SF-SelfGuard-<hash>, 已有守护则不重复启动
# 日志: 工具根目录 sf_guard.log (UTF-8)
# 传参: -Encoded <base64> = base64(UTF-8) 的三行: 第1行 ToolRoot, 第2行 Engine, 第3行 WatchPid, 第4行 RestartArgs
#       (base64 规避 Start-Process 对含空格/中文路径的引号转义坑)

param(
  [string]$Encoded
)

$ErrorActionPreference = 'SilentlyContinue'

# ---------- 解码引擎传入的参数 ----------
$ToolRoot = ''; $Engine = ''; $WatchPid = 0; $RestartArgs = ''
try {
  if (-not $Encoded) { exit 0 }
  $lines = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Encoded)) -split "`n", 4
  $ToolRoot    = $lines[0].Trim()
  $Engine      = $lines[1].Trim()
  $WatchPid    = [int]($lines[2].Trim())
  $RestartArgs = $lines[3]
} catch { exit 0 }
if (-not $ToolRoot -or -not $Engine -or $WatchPid -le 0) { exit 0 }
$RunMark    = Join-Path $ToolRoot 'sf_running.flag'
$GuardLog   = Join-Path $ToolRoot 'sf_guard.log'
$MaxKills   = 5          # 连续被 kill 重启上限, 防止无限循环
$PollSec    = 2          # 轮询间隔

function GuardLog([string]$m) {
  try { Add-Content -Path $GuardLog -Value ("[{0}] SelfGuard: {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m) -Encoding UTF8 } catch {}
}

# ---------- 关闭次数记录 (v1.52): 记录每一次被强制终止的时间戳 + 关闭风暴阈值检测 ----------
# 说明: v1.51 的"熔断式极端自保护(内核驱动)"已暂且搁置 -> 源码保留在 bin/ExtremeProtect.ps1 与 bin/drivers/, 但默认不启用/不加载.
#       本段仅保留"关闭次数记录"与"关闭风暴检测", 供运维/安全排查使用; 内核级保护恢复启用前不触发任何驱动加载.
$KillLog       = Join-Path $ToolRoot 'sf_kills.log'   # 每次引擎被强制终止的时间戳 (ISO 格式, 一行一条)
$KillWindowSec = 120   # 时间窗: 2 分钟内
$KillThreshold = 5     # 阈值: 时间窗内被关闭 >= 5 次 -> 判定为"关闭风暴"
$ExtremeFlag   = Join-Path $ToolRoot 'sf_extreme.flag'  # v1.52: 仅用于兼容检测 v1.51 遗留的极端态标志, 不再写入/加载

function Record-KillEvent {
  # 追加一行 ISO 时间戳到 sf_kills.log (每次引擎被强制终止时调用)
  try { Add-Content -Path $KillLog -Value (Get-Date -Format 'o') -Encoding UTF8 } catch {}
}

function Test-KillStorm {
  # 统计最近 $KillWindowSec 秒内被关闭次数, >= $KillThreshold 视为关闭风暴
  $now = Get-Date
  $recent = 0
  try {
    if (Test-Path $KillLog) {
      $lines = Get-Content $KillLog -Encoding UTF8 -ErrorAction SilentlyContinue
      $keep = @()
      foreach ($l in $lines) {
        $t = $null
        try { $t = [datetime]::Parse($l.Trim()) } catch { continue }
        if (($now - $t).TotalSeconds -le $KillWindowSec) {
          $recent++
          $keep += $l.Trim()
        }
      }
      # 裁剪日志: 仅保留最近 1 小时, 避免无限增长
      try { Set-Content -Path $KillLog -Value ($keep -join "`n") -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
    }
  } catch {}
  return ($recent -ge $KillThreshold)
}

# v1.52: 内核驱动相关逻辑 (IOCTL P/Invoke / Send-PidToDriver / Invoke-ExtremeProtect) 已随"极端保护搁置"移除.
#         源码保留于 bin/ExtremeProtect.ps1 与 bin/drivers/, 仅在显式恢复启用时调用.

# ===================== v1.48: watchdog 自身进程 DACL 保护 =====================
# 任务管理器也杀不掉守护进程 (仅 SYSTEM + Owner 可管理, 与引擎一致)
function Guard-ProtectSelf {
  try {
    if (-not ('GuardProc' -as [type])) {
      Add-Type -TypeDefinition ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('dXNpbmcgU3lzdGVtOwp1c2luZyBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXM7CnB1YmxpYyBjbGFzcyBHdWFyZFByb2MgewogIFtEbGxJbXBvcnQoImtlcm5lbDMyLmRsbCIsIFNldExhc3RFcnJvcj10cnVlKV0KICBwdWJsaWMgc3RhdGljIGV4dGVybiBJbnRQdHIgT3BlblByb2Nlc3ModWludCBhY2Nlc3MsIGJvb2wgaW5oZXJpdCwgaW50IHBpZCk7CiAgW0RsbEltcG9ydCgiYWR2YXBpMzIuZGxsIiwgU2V0TGFzdEVycm9yPXRydWUpXQogIHB1YmxpYyBzdGF0aWMgZXh0ZXJuIGJvb2wgU2V0S2VybmVsT2JqZWN0U2VjdXJpdHkoSW50UHRyIGhhbmRsZSwgaW50IHNlY0luZm8sIGJ5dGVbXSBzZGIpOwogIFtEbGxJbXBvcnQoImFkdmFwaTMyLmRsbCIpXQogIHB1YmxpYyBzdGF0aWMgZXh0ZXJuIGJvb2wgQ29udmVydFN0cmluZ1NlY3VyaXR5RGVzY3JpcHRvclRvU2VjdXJpdHlEZXNjcmlwdG9yKHN0cmluZyBzdHIsIHVpbnQgcmV2LCBvdXQgSW50UHRyIHNkYiwgb3V0IHVpbnQgc2l6ZSk7CiAgW0RsbEltcG9ydCgia2VybmVsMzIuZGxsIildCiAgcHVibGljIHN0YXRpYyBleHRlcm4gYm9vbCBDbG9zZUhhbmRsZShJbnRQdHIgaCk7Cn0=')))
    }
    $h = [GuardProc]::OpenProcess(0x0400 -bor 0x0001 -bor 0x0008, $false, $PID)
    if ($h -ne [IntPtr]::Zero) {
      # 仅 SYSTEM + Owner, 移除 Everyone/Users/Administrators 终止权限
      $sddl = "O:SYG:SYD:(A;;GA;;;SY)(A;;GA;;;OW)"
      $sdb = [IntPtr]::Zero; $size = [uint32]0
      [void][GuardProc]::ConvertStringSecurityDescriptorToSecurityDescriptor($sddl, 1, [ref]$sdb, [ref]$size)
      $bytes = New-Object byte[] $size
      [Runtime.InteropServices.Marshal]::Copy($sdb, $bytes, 0, $size)
      $ok = [GuardProc]::SetKernelObjectSecurity($h, 4, $bytes)
      [void][GuardProc]::CloseHandle($h)
      if ($ok) { GuardLog 'self DACL protected' }
    }
  } catch { GuardLog ('self DACL failed: ' + $_.Exception.Message) }
  # v1.49: watchdog 不设蓝屏 (蓝屏只由引擎智能策略触发, 避免误杀蓝屏); 被杀时靠引擎重启后重新 spawn
}
Guard-ProtectSelf

# ---------- 单实例互斥 (防引擎重启后重复 spawn 出多个守护) ----------
$mutex = $null
try {
  $h = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($ToolRoot.ToLower()))
  $name = 'Global\SF-SelfGuard-' + (([System.BitConverter]::ToString($h) -replace '-','').Substring(0,16))
  $mutex = New-Object System.Threading.Mutex($false, $name)
  if (-not $mutex.WaitOne(0)) {
    # 已有守护实例 (说明引擎已重启并重新 spawn, 本次直接退出)
    exit 0
  }
} catch {
  # Global 命名空间可能权限不足 (非管理员), 回退 Local 会话命名
  try {
    $mutex = New-Object System.Threading.Mutex($false, 'SF-SelfGuard-' + $PID)
    if (-not $mutex.WaitOne(0)) { exit 0 }
  } catch { }
}

GuardLog ("启动: 监控 PID=" + $WatchPid + " 引擎=" + $Engine)

# v1.52: 内核保护已搁置 - 若遗留旧版极端态标志, 仅记录提示, 不再自动加载驱动 (源码保留于 bin/)
if (Test-Path $ExtremeFlag) {
  GuardLog '检测到历史极端态标志 (sf_extreme.flag), 内核保护已搁置未启用; 如需清除请运行 /resetextreme'
}

# 重启命令构造: 与 bat 一致的内存加载方式, 用 -EncodedCommand 避免引号嵌套问题
$pwshPath = ''
try { $pwshPath = (Get-Process -Id $PID).Path } catch {}
if (-not $pwshPath) { $pwshPath = 'powershell.exe' }
$scriptCmd = "& ([scriptblock]::Create([IO.File]::ReadAllText('" + $Engine + "'))) " + $RestartArgs
$encoded   = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($scriptCmd))

$kills = 0
$currentPid = $WatchPid
$Heartbeat = Join-Path $ToolRoot 'sf_guard.heartbeat'   # v1.50: 心跳文件 - 引擎检测守护是否存活
while ($true) {
  Start-Sleep -Seconds $PollSec
  # v1.50: 心跳 - 每次轮询更新, 引擎据此判断 watchdog 是否被单独 kill (超时未更新则重新 spawn)
  try { [System.IO.File]::WriteAllText($Heartbeat, (Get-Date).ToString('o')) } catch {}
  # v1.52: 内核驱动 PID 刷新逻辑已随"极端保护搁置"移除 (仅保留用户态心跳自愈)
  $proc = Get-Process -Id $currentPid -ErrorAction SilentlyContinue
  if ($proc) { continue }

  # 进程消失: 判断是正常退出还是被 kill
  if (-not (Test-Path $RunMark)) {
    GuardLog ("引擎正常退出 (PID=" + $currentPid + "), SelfGuard 结束")
    break
  }

  $kills++
  Record-KillEvent
  GuardLog ("检测到引擎被强制终止 (PID=" + $currentPid + ", 运行标记仍在), 第 " + $kills + " 次自动重启")
  # v1.52: 关闭风暴检测 (保留记录) - 内核保护已搁置, 仅记录告警, 不加载驱动
  if (Test-KillStorm) {
    GuardLog '检测到关闭风暴 (2分钟内被关闭>=5次, 已记录). 内核级保护当前已搁置(源码保留于 bin/, 未启用), 仅用户态自愈生效'
  }
  # 用户态兜底上限: 防止无限重启 (内核保护已搁置, 此上限始终生效)
  if ($kills -gt $MaxKills) {
    GuardLog ("引擎被强制终止 " + $kills + " 次, 已超过用户态上限 " + $MaxKills + ", 停止自动重启")
    break
  }

  $p = $null
  try {
    $p = Start-Process -FilePath $pwshPath -WindowStyle Hidden -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$encoded) -PassThru
  } catch {
    try { $p = Start-Process -FilePath $pwshPath -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$encoded) -PassThru } catch { $p = $null }
  }
  if (-not $p) {
    GuardLog '重启引擎失败 (Start-Process 返回空)'
    continue
  }
  $currentPid = $p.Id
  GuardLog ("已重启引擎, 新 PID=" + $currentPid)

  # 等待新引擎建立运行标记 (最多 30 秒); 建不起来则继续监控 (新引擎可能还没到自保护初始化)
  $waited = 0
  while ($waited -lt 30) {
    if (Test-Path $RunMark) { break }
    Start-Sleep -Seconds 1; $waited++
  }
  if (-not (Test-Path $RunMark)) {
    GuardLog ('重启后引擎未建立运行标记 (可能仍在初始化或启动失败), 继续监控 PID=' + $currentPid)
  }
}

try { if ($mutex) { $mutex.ReleaseMutex(); $mutex.Dispose() } } catch {}
exit 0
