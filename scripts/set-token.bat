@echo off
REM ============================================
REM 配置 GitHub PAT 到 Windows 用户环境变量
REM 此脚本只写 GITHUB_TOKEN，不会被 git 跟踪
REM ============================================

set TOKEN=
set /p TOKEN=请输入 GitHub Personal Access Token: 

if "%TOKEN%"=="" (
    echo [错误] Token 不能为空
    pause
    exit /b 1
)

REM 写入用户级环境变量（永久生效，仅当前用户可见）
setx GITHUB_TOKEN "%TOKEN%" >nul

echo.
echo [成功] GITHUB_TOKEN 已保存到用户环境变量
echo 提示：新开命令行窗口或重启 IDE 后生效
echo 之后可直接运行 scripts\push-all.bat 同时推两个仓库
echo.
pause
