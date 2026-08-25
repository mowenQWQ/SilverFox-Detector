# ============================================================
#  恢复杀毒软件功能 - 端到端测试脚本
#  模拟"银狐木马限制安全软件"的常见破坏行为, 用于验证
#  本工具的「恢复杀毒软件 (/restoreav)」能否检测并修复。
#
#  用法 (管理员 PowerShell, 测试后必执行"清理"还原现场):
#    powershell -ExecutionPolicy Bypass -File restoreav_模拟测试.ps1 破坏
#    powershell -ExecutionPolicy Bypass -File restoreav_模拟测试.ps1 检查
#    (可选) 运行工具 -> 恢复杀毒软件 (/restoreav) -> 再看检查结果
#    powershell -ExecutionPolicy Bypass -File restoreav_模拟测试.ps1 清理
# ============================================================
param([string]$Action = '破坏')

$ErrorActionPreference = 'SilentlyContinue'
$bak = Join-Path $env:TEMP ('restoreav_test_backup_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.txt')
$hostsBak = Join-Path $env:TEMP ('restoreav_test_hosts_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.bak')
$hosts = "$env:SystemRoot\System32\drivers\etc\hosts"

# ---- 模拟项定义 (名称/键/值) ----
$items = @(
    @{ Name='Defender策略-Realtime';      Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'; Val='DisableRealtimeMonitoring'; Type='DWord'; Val2=1 },
    @{ Name='Defender策略-SecurityCenter';Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'; Val='DisableSecurityCenter'; Type='DWord'; Val2=1 },
    @{ Name='Defender策略子键-Behavior';  Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Val='DisableBehaviorMonitoring'; Type='DWord'; Val2=1 },
    @{ Name='Defender客户端-Realtime';    Key='HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection'; Val='DisableRealtimeMonitoring'; Type='DWord'; Val2=1 },
    @{ Name='任务管理器禁用';             Key='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Val='DisableTaskMgr'; Type='DWord'; Val2=1 },
    @{ Name='WindowsUpdate禁用访问';      Key='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; Val='DisableWindowsUpdateAccess'; Type='DWord'; Val2=1 },
    @{ Name='Defender排除项-恶意路径';    Key='HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'; Val='C:\TempAvTest\evil.exe'; Type='String'; Val2='C:\TempAvTest\evil.exe' },
    @{ Name='IFEO劫持-360Tray';           Key='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\360Tray.exe'; Val='Debugger'; Type='String'; Val2='C:\fake\dbg.exe' }
)

# ---- 管理员检查 ----
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host '  [错误] 请以管理员身份运行本脚本 (修改 HKLM 需要管理员)' -ForegroundColor Red
    exit 1
}

switch ($Action) {
    '破坏' {
        Write-Host '=== 模拟"银狐限制安全软件"破坏行为 ===' -ForegroundColor Cyan
        $log = @()
        foreach ($it in $items) {
            if (Test-Path -LiteralPath $it.Key) {
                $old = (Get-ItemProperty -Path $it.Key -Name $it.Val -ErrorAction SilentlyContinue).($it.Val)
                if ($null -ne $old) {
                    $log += ('OLD|' + $it.Key + '|' + $it.Val + '|' + $old)
                    Write-Host ('  [注入] ' + $it.Name + ' -> ' + $it.Key + ' -> ' + $it.Val + ' (原值备份)') -ForegroundColor Yellow
                } else {
                    $log += ('NEW|' + $it.Key + '|' + $it.Val + '|')
                    Write-Host ('  [注入] ' + $it.Name + ' -> ' + $it.Key + ' -> ' + $it.Val + ' (新建)') -ForegroundColor Yellow
                }
            } else {
                New-Item -Path $it.Key -Force | Out-Null
                $log += ('NEW|' + $it.Key + '|' + $it.Val + '|')
                Write-Host ('  [注入] ' + $it.Name + ' -> ' + $it.Key + ' -> ' + $it.Val + ' (新建键+值)') -ForegroundColor Yellow
            }
            Set-ItemProperty -Path $it.Key -Name $it.Val -Value $it.Val2 -Type $it.Type -Force
        }
        # hosts 注入 (备份后加行)
        if (Test-Path -LiteralPath $hosts) {
            Copy-Item -LiteralPath $hosts -Destination $hostsBak -Force
            Add-Content -LiteralPath $hosts -Value '0.0.0.0 defender.microsoft.com' -Encoding ASCII
            Write-Host '  [注入] hosts -> 0.0.0.0 defender.microsoft.com' -ForegroundColor Yellow
        }
        Set-Content -LiteralPath $bak -Value $log -Encoding UTF8
        Write-Host ''
        Write-Host ('  模拟注入完成 (备份: ' + $bak + ')') -ForegroundColor Green
        Write-Host '  下一步: 运行本工具 -> 恢复杀毒软件 (/restoreav), 然后执行本脚本 检查 验证修复' -ForegroundColor Gray
    }
    '检查' {
        Write-Host '=== 检查模拟项当前状态 ===' -ForegroundColor Cyan
        foreach ($it in $items) {
            $v = (Get-ItemProperty -Path $it.Key -Name $it.Val -ErrorAction SilentlyContinue).($it.Val)
            if ($null -ne $v) {
                Write-Host ('  [仍存在=' + $v + '] ' + $it.Name) -ForegroundColor Red
            } else {
                Write-Host ('  [已清除] ' + $it.Name) -ForegroundColor Green
            }
        }
        $hostLine = Select-String -LiteralPath $hosts -Pattern 'defender.microsoft.com' -ErrorAction SilentlyContinue
        if ($hostLine) { Write-Host '  [仍存在] hosts 劫持行' -ForegroundColor Red } else { Write-Host '  [已清除] hosts 劫持行' -ForegroundColor Green }
    }
    '清理' {
        Write-Host '=== 还原现场 (清理全部模拟项) ===' -ForegroundColor Cyan
        if (Test-Path -LiteralPath $bak) {
            foreach ($line in (Get-Content -LiteralPath $bak)) {
                $p = $line -split '\|'
                if ($p.Count -ge 3) {
                    if ($p[0] -eq 'NEW') {
                        Remove-ItemProperty -Path $p[1] -Name $p[2] -Force -ErrorAction SilentlyContinue
                        Write-Host ('  [清理] 删除 ' + $p[2]) -ForegroundColor Gray
                    } elseif ($p[0] -eq 'OLD') {
                        if ($p.Count -ge 4 -and $p[3] -ne '') {
                            Set-ItemProperty -Path $p[1] -Name $p[2] -Value $p[3] -Force -ErrorAction SilentlyContinue
                        } else {
                            Remove-ItemProperty -Path $p[1] -Name $p[2] -Force -ErrorAction SilentlyContinue
                        }
                        Write-Host ('  [还原] ' + $p[2]) -ForegroundColor Gray
                    }
                }
            }
        } else {
            Write-Host '  无备份文件, 按模拟项清单强制清理' -ForegroundColor Yellow
            foreach ($it in $items) {
                Remove-ItemProperty -Path $it.Key -Name $it.Val -Force -ErrorAction SilentlyContinue
            }
        }
        if (Test-Path -LiteralPath $hostsBak) {
            Copy-Item -LiteralPath $hostsBak -Destination $hosts -Force
            Write-Host '  [清理] hosts 已还原' -ForegroundColor Gray
        } else {
            $hostLine = Select-String -LiteralPath $hosts -Pattern 'defender.microsoft.com' -ErrorAction SilentlyContinue
            if ($hostLine) {
                $kept = Get-Content -LiteralPath $hosts | Where-Object { $_ -notmatch 'defender\.microsoft\.com' }
                Set-Content -LiteralPath $hosts -Value $kept -Encoding ASCII
            }
        }
        Write-Host '  现场已还原' -ForegroundColor Green
    }
    default {
        Write-Host '用法: 本脚本 破坏 | 检查 | 清理' -ForegroundColor Yellow
    }
}
