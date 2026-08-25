# ===================== SilverFox ExtremeProtect (Windows) v1.51 =====================
# 状态: v1.52 起已暂停启用 (源码保留, 暂不调用/不加载). 仅当显式恢复极端自保护流程时才被调用.
# 熔断式极端自保护(历史设计): 仅在被疯狂关闭(2分钟内>=5次)后由 watchdog 调用, 或显式 /extremeprotect 触发.
#
# 职责:
#   1) 检查管理员权限 (加载内核驱动 / 修改 BCD 必须)
#   2) 检查 TESTSIGNING (测试签名模式) 是否开启
#      - 未开启: bcdedit /set testsigning on (需重启生效), 写 extreme flag, 提示用户重启
#      - 已开启: 加载 sfguard.sys 内核驱动 (ObRegisterCallbacks 保护引擎进程不被结束)
#   3) 通过 IOCTL 把受保护 PID (引擎 + watchdog) 发给驱动
#   4) 写 sf_extreme.flag 持久标志 (重启后由 watchdog 自动恢复极端态)
#
# 合规警告: 本脚本会开启 TESTSIGNING (系统级变更, 允许测试签名驱动加载, 降低系统内核完整性),
#           属于"不太合规"的应急手段. 仅用于防御本检测引擎被恶意软件/攻击者持续关闭, 非默认启用.
#           内核驱动需用户自行在 WDK 环境编译 (bin\drivers\build_driver.bat), 未经编译则无法加载.

param(
  [string]$ToolRoot   = '',
  [int]$EnginePid     = 0,
  [int]$WatchdogPid   = 0,
  [switch]$RefreshPid       # 仅刷新受保护 PID 到已加载的驱动 (不重复加载)
)

$ErrorActionPreference = 'SilentlyContinue'

# ToolRoot 推断: 脚本位于 bin\ExtremeProtect.ps1 -> 父目录的父目录
if (-not $ToolRoot) {
  $here = Split-Path $MyInvocation.MyCommand.Definition -Parent
  $ToolRoot = Split-Path $here -Parent
}
$GuardLog    = Join-Path $ToolRoot 'sf_guard.log'
$ExtremeFlag = Join-Path $ToolRoot 'sf_extreme.flag'
$DriverPath  = Join-Path $ToolRoot 'bin\drivers\sfguard.sys'

function ELog([string]$m) {
  try { Add-Content -Path $GuardLog -Value ("[{0}] ExtremeProtect: {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m) -Encoding UTF8 } catch {}
  Write-Host ("  [极端保护] " + $m) -ForegroundColor Magenta
}

# ---------- IOCTL P/Invoke: 把受保护 PID 发给驱动 (\.\sfguard, CTL_CODE 0x222000) ----------
$ioctlSrc = @'
using System;
using System.Runtime.InteropServices;
public class SfIoctl {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
  public static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode, byte[] lpInBuffer, int nInBufferSize, byte[] lpOutBuffer, int nOutBufferSize, ref int lpBytesReturned, IntPtr lpOverlapped);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool CloseHandle(IntPtr hObject);
  public const uint GENERIC_READ  = 0x80000000;
  public const uint GENERIC_WRITE = 0x40000000;
  public const uint OPEN_EXISTING = 3;
  public const uint FILE_ATTRIBUTE_NORMAL = 0x80;
  public const uint FILE_SHARE_READ  = 1;
  public const uint FILE_SHARE_WRITE = 2;
}
'@
try { if (-not ('SfIoctl' -as [type])) { Add-Type -TypeDefinition $ioctlSrc } } catch {}

function Send-PidToDriver([int]$pidVal) {
  try {
    $h = [SfIoctl]::CreateFile('\\.\sfguard', [SfIoctl]::GENERIC_READ -bor [SfIoctl]::GENERIC_WRITE,
            [SfIoctl]::FILE_SHARE_READ -bor [SfIoctl]::FILE_SHARE_WRITE, [IntPtr]::Zero,
            [SfIoctl]::OPEN_EXISTING, [SfIoctl]::FILE_ATTRIBUTE_NORMAL, [IntPtr]::Zero)
    if ($h -eq [IntPtr]::Zero -or $h -eq [IntPtr]::MinusOne) { return $false }
    $inBuf = [BitConverter]::GetBytes([uint32]$pidVal)
    $outBuf = New-Object byte[] 4
    $ret = 0
    $ok = [SfIoctl]::DeviceIoControl($h, 0x222000, $inBuf, $inBuf.Length, $outBuf, $outBuf.Length, [ref]$ret, [IntPtr]::Zero)
    [SfIoctl]::CloseHandle($h)
    return $ok
  } catch { return $false }
}

function Write-ExtremeFlag([string]$state) {
  try {
    Set-Content -Path $ExtremeFlag -Value ("triggered=" + (Get-Date -Format 'o') + "`nengine_pid=" + $EnginePid + "`nwatchdog_pid=" + $WatchdogPid + "`nstate=" + $state) -Encoding UTF8
  } catch {}
}

# ---------- 仅刷新 PID (驱动已加载) ----------
if ($RefreshPid) {
  $ok1 = $false; $ok2 = $false
  if ($EnginePid   -gt 0) { $ok1 = Send-PidToDriver $EnginePid }
  if ($WatchdogPid -gt 0) { $ok2 = Send-PidToDriver $WatchdogPid }
  if ($ok1) { ELog ('刷新引擎受保护 PID=' + $EnginePid) }
  if ($ok2) { ELog ('刷新 watchdog 受保护 PID=' + $WatchdogPid) }
  if (-not $ok1 -and -not $ok2) { ELog '刷新 PID 失败 (驱动可能未加载或设备未就绪)' }
  exit 0
}

# ---------- 1) 管理员检查 ----------
$isAdmin = $false
try {
  $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
  $isAdmin = $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {}
if (-not $isAdmin) {
  ELog '需要管理员权限才能加载内核驱动/修改 BCD, 退回用户态 DACL+心跳自愈'
  exit 1
}

# ---------- 2) 检查 TESTSIGNING ----------
function Test-TestSigning {
  try {
    $out = & bcdedit.exe /enum '{current}' 2>$null
    foreach ($line in $out) {
      if ($line -match 'testsigning\s+(\w+)') { return ($Matches[1] -eq 'Yes') }
    }
  } catch {}
  return $false
}

$testSigning = Test-TestSigning
if (-not $testSigning) {
  ELog '测试签名模式(TESTSIGNING)未开启, 尝试开启 (需重启生效)...'
  try { & bcdedit.exe /set testsigning on 2>$null } catch {}
  $testSigning = Test-TestSigning
  if (-not $testSigning) {
    ELog '开启 TESTSIGNING 失败 (可能无权限或被策略阻止), 退回用户态保护'
    exit 2
  }
  # 写 extreme flag 持久化: 重启后 TESTSIGNING 生效, watchdog 会自动重新触发并加载驱动
  Write-ExtremeFlag 'testsigned_pending_reboot'
  ELog '已开启 TESTSIGNING 并写入极端态标志; 请重启系统使驱动可加载 (重启后 watchdog 自动加载 sfguard.sys)'
  exit 0
}

# ---------- 3) 已开启 TESTSIGNING: 加载内核驱动 ----------
if (-not (Test-Path $DriverPath)) {
  ELog ('内核驱动缺失: ' + $DriverPath + '  请先在 WDK 环境运行 bin\drivers\build_driver.bat 编译 sfguard.sys')
  Write-ExtremeFlag 'driver_missing'
  exit 3
}

try { & sc.exe delete sfguard 2>$null } catch {}
Start-Sleep -Seconds 1
$createOut = & sc.exe create sfguard type= kernel start= demand binPath= $DriverPath 2>&1
ELog ('sc create: ' + ($createOut -join ' '))
$startOut = & sc.exe start sfguard 2>&1
ELog ('sc start: ' + ($startOut -join ' '))

$loaded = $false
try {
  $svc = Get-Service -Name 'sfguard' -ErrorAction SilentlyContinue
  if ($svc -and $svc.Status -eq 'Running') { $loaded = $true }
} catch {}
if (-not $loaded) {
  ELog '驱动未能运行 (签名不符/系统策略/未开启 TESTSIGNING), 退回用户态保护'
  Write-ExtremeFlag 'driver_load_failed'
  exit 4
}

# ---------- 4) 通知驱动受保护 PID ----------
Start-Sleep -Seconds 2
if ($EnginePid   -gt 0) { if (Send-PidToDriver $EnginePid)   { ELog ('已通知驱动保护引擎 PID=' + $EnginePid) } }
if ($WatchdogPid -gt 0) { if (Send-PidToDriver $WatchdogPid) { ELog ('已通知驱动保护 watchdog PID=' + $WatchdogPid) } }

Write-ExtremeFlag 'active'
ELog '极端自保护已激活: 内核驱动 sfguard.sys 已加载, 引擎进程受内核级保护 (TerminateProcess 将被拒绝)'
exit 0
