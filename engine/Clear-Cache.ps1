param(
  [switch]$Yes
)

# ===================== 银狐木马检测 - 哈希缓存清理工具 v1.21 =====================
# 功能: 删除哈希缓存 (C盘主缓存 + 工具目录副本), 下次检测将重新计算
# 用法: 双击 清理缓存.bat, 或 powershell -File Clear-Cache.ps1
# 可选: -Yes 跳过确认直接删除



try { [Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(936) } catch {
  try { [System.Text.Encoding]::RegisterProvider([System.Text.CodePagesEncodingProvider]::Instance); [Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(936) } catch {}   # v1.42: pwsh7/.NET Core 需注册代码页
}

$toolRoot = Split-Path (Split-Path $PSCommandPath -Parent) -Parent
$envLocalApp = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } elseif ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }   # v1.42: 与引擎 EnvUser 回退链完全一致
$cacheDir = Join-Path $envLocalApp 'SilverFoxDetector'
$CacheFile = Join-Path $cacheDir 'hash_cache.txt'
$Mirror = Join-Path $toolRoot 'sf_hash_cache.txt'

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  银狐木马检测 - 哈希缓存清理工具"                          -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "  将删除以下哈希缓存文件:"
Write-Host ("    [C盘主缓存] " + $CacheFile) -ForegroundColor Gray
Write-Host ("    [工具副本] " + $Mirror) -ForegroundColor Gray
Write-Host ""
Write-Host "  删除后下次检测将重新计算全部文件哈希 (较慢)."
Write-Host "  若缓存异常/体积过大/误判, 可清理后重建."
Write-Host ""

if (-not $Yes) {
  $ans = Read-Host "  确认删除? 输入 DELETE 确认, 其他任意键取消"
  if ($ans -ne 'DELETE') {
    Write-Host "  已取消, 未删除任何文件。" -ForegroundColor Yellow
    Read-Host | Out-Null
    return 0
  }
}

$removed = 0; $missing = 0
foreach ($f in @($CacheFile, $Mirror)) {
  if (Test-Path $f) {
    try {
      Remove-Item -Path $f -Force -ErrorAction Stop
      Write-Host ("  [OK] 已删除: " + $f) -ForegroundColor Green
      $removed++
    } catch {
      Write-Host ("  [失败] 无法删除: " + $f + " : " + $_.Exception.Message) -ForegroundColor Red
    }
  } else {
    Write-Host ("  [跳过] 不存在: " + $f) -ForegroundColor DarkYellow
    $missing++
  }
}

Write-Host ""
Write-Host "============================================================"
Write-Host ("  清理完成: 删除 " + $removed + " 个, 不存在 " + $missing + " 个")
Write-Host "============================================================"
Write-Host ""
Write-Host "  提示: 下次运行 银狐木马检测.bat 会自动重建缓存."
Write-Host ""
Write-Host "按任意键关闭..."
Read-Host | Out-Null
return 0