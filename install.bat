@echo off
REM ═══════════════════════════════════════════════════════════
REM  Blaze Installer — Windows
REM ═══════════════════════════════════════════════════════════

echo.
echo     ██████╗ ██╗      █████╗ ███████╗███████╗
echo     ██╔══██╗██║     ██╔══██╗╚══███╔╝██╔════╝
echo     ██████╔╝██║     ███████║  ███╔╝ █████╗
echo     ██╔══██╗██║     ██╔══██║ ███╔╝  ██╔══╝
echo     ██████╔╝███████╗██║  ██║███████╗███████╗
echo     ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝
echo.
echo     Installer v2.1
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    python3 --version >nul 2>&1
    if errorlevel 1 (
        echo   [!] Python 3.8+ required but not found.
        echo       Download: https://www.python.org/downloads/
        pause
        exit /b 1
    )
    set PYTHON=python3
) else (
    set PYTHON=python
)

echo   [+] Python found
echo.
echo   Select installation method:
echo.
echo     1) pip install (recommended)
echo     2) Standalone binary (PyInstaller)
echo     3) Development mode
echo.
set /p choice="  Choice [1]: "
if "%choice%"=="" set choice=1

if "%choice%"=="1" (
    echo.
    echo   Installing with pip...
    %PYTHON% -m pip install "%~dp0" --quiet
    echo   [+] Installed! Run with: blaze -u https://target.com
)
if "%choice%"=="2" (
    echo.
    echo   Building standalone binary...
    %PYTHON% -m pip install pyinstaller --quiet
    %PYTHON% "%~dp0build.py"
)
if "%choice%"=="3" (
    echo.
    echo   Installing in development mode...
    %PYTHON% -m pip install -e "%~dp0" --quiet
    echo   [+] Dev install complete! Run with: blaze -u https://target.com
)

echo.
echo   Installation complete!
echo.
pause
