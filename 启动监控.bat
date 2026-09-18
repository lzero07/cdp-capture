@echo off
chcp 65001 >nul
cd /d "%~dp0"
rem 用法1: 双击直接运行 — 记录全部请求
rem 用法2: 命令行 node monitor.mjs https://... --only 关键字1 关键字2  — 打开指定网址且只记录命中关键字的请求
node monitor.mjs %*
pause
