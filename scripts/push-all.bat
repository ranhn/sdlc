@echo off
REM ============================================
REM SDLC 平台 - 双仓库推送脚本
REM 同时推送到 GitHub (HTTPS + PAT) 和 GitLab (SSH)
REM
REM 用法：
REM   push-all.bat                    推送当前分支到默认分支
REM   push-all.bat feature-xxx        推送当前分支到 feature-xxx
REM   push-all.bat HEAD~3..HEAD       推送指定范围
REM
REM 首次使用：双击 set-token.bat 配置 GitHub PAT
REM ============================================

setlocal enabledelayedexpansion

REM 读取 GitHub PAT（从 Windows 用户环境变量）
if "%GITHUB_TOKEN%"=="" (
    echo [错误] 未设置 GITHUB_TOKEN 环境变量
    echo 请双击运行 scripts\set-token.bat 配置
    exit /b 1
)

REM 解析参数（默认推送 HEAD 到同名分支）
set "RANGE=%*"
if "%RANGE%"=="" set "RANGE=HEAD"

REM 切到仓库根目录
cd /d "%~dp0\.."

echo === [1/2] 推送到 GitHub (https://github.com/ranhn/sdlc) ===
set GIT_TERMINAL_PROMPT=0
git push https://ranhn:%GITHUB_TOKEN%@github.com/ranhn/sdlc.git %RANGE%
if errorlevel 1 (
    echo [失败] GitHub 推送失败
    exit /b 1
)

echo.
echo === [2/2] 推送到 GitLab (git@fangcun.vesync.cn:ning.ran/vesync-sdlc) ===
git push gitlab %RANGE%
if errorlevel 1 (
    echo [失败] GitLab 推送失败
    exit /b 1
)

echo.
echo === 完成 ===
endlocal
