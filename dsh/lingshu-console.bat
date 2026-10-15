@echo off
rem ============================================================
rem lingshu-console.bat - 灵枢记忆控制台（本机只读网页）
rem
rem 用法：双击即可。会自动找到记忆库并在默认浏览器打开 http://127.0.0.1:8765/
rem       （端口被占用时自动换一个，实际地址见窗口）。
rem 指定记忆库：lingshu-console.bat --root "D:\我的记忆"
rem 解释器：环境变量 MDCG_PYTHON（与 MCP 配置同名），缺省 python
rem       （与 src/lib/python_path.ts 同口径，不做 PATH 扫描回退）。
rem 控制台只读：不会修改、删除任何记忆。关闭本窗口即退出。
rem ============================================================
chcp 65001 >nul
setlocal
set "PYTHONPATH=%~dp0..;%PYTHONPATH%"
set "PYTHONUTF8=1"
set "LS_PY=python"
if defined MDCG_PYTHON set "LS_PY=%MDCG_PYTHON%"
title Lingshu Memory Console
"%LS_PY%" -X utf8 -m md_cg.console %*
if not errorlevel 1 goto ok
echo.
echo [lingshu-console] exited with an error (see message above).
echo If Python is missing: install Python 3.10+ (tick "Add to PATH") or set MDCG_PYTHON.
echo Press any key to close.
pause >nul
endlocal
exit /b 1
:ok
endlocal
exit /b 0
