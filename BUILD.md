# 构建说明 (BUILD)

## 环境
- Go 1.21+ (GOPROXY=https://goproxy.cn 或官方)
- goversioninfo (https://github.com/josephspurrier/goversioninfo) 用于资源编译
- Windows 10/11 构建机 (纯静态 Win32 API, 兼容 Win7 运行)

## 编译主程序 (main.go + selfguard_hook.go + versioninfo.json)
```powershell
# 安装资源工具
go install github.com/josephspurrier/goversioninfo@latest

# 生成资源 (versioninfo.json -> resource.syso)
goversioninfo -o resource.syso versioninfo.json

# 三档构建 (tier=1 主程序 / 2 备用 / 3 加强版)
go build -ldflags "-s -w -X main.buildTierStr=1 -H windowsgui" -o 顽固木马扫描专杀-银狐特攻.exe .
go build -ldflags "-s -w -X main.buildTierStr=2 -H windowsgui" -o 如果主程序打不开点我.exe .
go build -ldflags "-s -w -X main.buildTierStr=3 -H windowsgui" -o 如果主程序打不开点我-加强版.com .
```

## 引擎
- engine/SilverFoxDetect.ps1 由 bat 调用, 依赖 PowerShell 5.1+ (或 7)
- ioc/known_c2.txt / known_hashes.txt 为 IOC 库 (每行一条, 支持 # 注释; known_* 手动维护, auto_* 由 /update 生成)

## 目录约定
- 主程序 exe 与 legacy/ 目录同级 (传统布局) 或按 engine/ + ioc/ 平铺后由 bat 自动定位
- 引擎通过 $PSCommandPath 自动定位 bin 目录, 无需硬编码

## 版本
- 全链版本: main.go AppTitle/buildTag + engine 头注释 + versioninfo.json 需同步
- manifest (完整性清单) 由发布脚本 `generate-integrity.ps1` 生成（与引擎/main 同 salt+签名算法）; 路径: legacy/integrity.manifest（改动任何工具文件后，对发布包 legacy 目录重跑该脚本即可重签，避免自检误报"被篡改"）
