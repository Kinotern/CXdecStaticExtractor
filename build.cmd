@echo off
setlocal enabledelayedexpansion
chcp 65001 > nul

:menu
cls
echo ========================================================
echo   HXV4 XP3 Extractor (Rust Edition) - One-Click Build
echo ========================================================
echo.
echo [1] Build Project (Release)
echo [2] Clean Project
echo [0] Exit
echo.

set /p choice="Enter your choice (0-2): "

:: Set robust directories based on script location
set "PROJECT_ROOT=%~dp0"
set "RUST_DIR=%PROJECT_ROOT%src-tauri"
set "OUT_DIR=%PROJECT_ROOT%Release"
set "SCHEME_DIR=%PROJECT_ROOT%scheme"

if "%choice%"=="1" goto build_project
if "%choice%"=="2" goto clean
if "%choice%"=="0" goto end_script

echo Invalid choice.
echo.
pause
goto menu

:build_project
echo.
echo [1/2] Building the 32-bit Rust Analyzer...
call rustup target add i686-pc-windows-msvc >nul 2>&1
cd /d "%PROJECT_ROOT%cxdec-rs-analyzer"
call cargo build --release --target i686-pc-windows-msvc
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Analyzer compilation failed!
    pause >nul
    goto menu
)

if not exist "%SCHEME_DIR%" mkdir "%SCHEME_DIR%"
copy /y "%PROJECT_ROOT%cxdec-rs-analyzer\target\i686-pc-windows-msvc\release\Cxdecanalyzer.exe" "%SCHEME_DIR%\Cxdecanalyzer.exe" >nul

echo.
echo [2/2] Building the Rust backend and embedding the UI...
cd /d "%RUST_DIR%"
call cargo build --release
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] GUI Compilation failed!
    pause >nul
    goto menu
)

:: Assemble release folder
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"
copy /y "%RUST_DIR%\target\release\hxv4-xp3-extractor-rust.exe" "%OUT_DIR%\hxv4xp3Extractor.exe" >nul

if exist "%SCHEME_DIR%" (
    if not exist "%OUT_DIR%\scheme" mkdir "%OUT_DIR%\scheme"
    xcopy /y /e /q "%SCHEME_DIR%\*" "%OUT_DIR%\scheme\" >nul
)

:: Ensure the CLI tool is also placed directly into the final release scheme folder
copy /y "%PROJECT_ROOT%cxdec-rs-analyzer\target\i686-pc-windows-msvc\release\Cxdecanalyzer.exe" "%OUT_DIR%\scheme\Cxdecanalyzer.exe" >nul

:: Copy the unpacking CLI tool to the scheme folder
copy /y "%RUST_DIR%\target\release\cli.exe" "%OUT_DIR%\scheme\cxdec-cli.exe" >nul

echo.
echo ========================================================
echo   Build Complete! 
echo   Your standalone application is ready at:
echo   %OUT_DIR%\hxv4xp3Extractor.exe
echo ========================================================
echo Press any key to return to menu...
pause >nul
goto menu

:clean
echo.
echo Cleaning cargo projects...
cd /d "%RUST_DIR%"
call cargo clean
cd /d "%PROJECT_ROOT%cxdec-rs-analyzer"
call cargo clean
echo Clean completed.
echo.
echo Press any key to return to menu...
pause >nul
goto menu

:end_script
