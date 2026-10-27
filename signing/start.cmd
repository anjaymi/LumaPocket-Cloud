@echo off
setlocal
set "TASK_PYTHON=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
if not exist "%TASK_PYTHON%" set "TASK_PYTHON=python"
if "%~1"=="" (
  "%TASK_PYTHON%" "%~dp0local.py" onboard
) else (
  "%TASK_PYTHON%" "%~dp0local.py" %*
)
set "TASK_EXIT=%ERRORLEVEL%"
if not "%TASK_EXIT%"=="0" pause
exit /b %TASK_EXIT%
