@echo off
REM setup.bat - Setup script for pum-aws (Windows)
REM This script creates a virtual environment and installs dependencies

setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
set PROJECT_DIR=%SCRIPT_DIR%..
set VENV_DIR=%PROJECT_DIR%\venv

pushd "%PROJECT_DIR%"

echo === PUM-AWS Setup Script ===
echo Project directory: %PROJECT_DIR%
echo Virtual environment directory: %VENV_DIR%

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.6+ and try again
    pause
    exit /b 1
)

REM Get Python version
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set python_version=%%i
echo Python version: %python_version%

REM Create virtual environment if it doesn't exist
if not exist "%VENV_DIR%" (
    echo Creating virtual environment...
    python -m venv "%VENV_DIR%"
    if %errorlevel% neq 0 (
        echo Error: Failed to create virtual environment
        pause
        exit /b 1
    )
    echo Virtual environment created successfully
) else (
    echo Virtual environment already exists
)

REM Activate virtual environment
echo Activating virtual environment...
call "%VENV_DIR%\Scripts\activate.bat"

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip

REM Install dependencies
echo Installing dependencies from requirements.txt...
if exist "%PROJECT_DIR%\requirements.txt" (
    pip install -r "%PROJECT_DIR%\requirements.txt"
    if %errorlevel% neq 0 (
        echo Error: Failed to install dependencies
        pause
        exit /b 1
    )
    echo Dependencies installed successfully
) else (
    echo Warning: requirements.txt not found
)

echo.
echo === Setup Complete ===
echo Virtual environment is ready at: %VENV_DIR%
echo To activate manually: %VENV_DIR%\Scripts\activate.bat
echo To run the application: scripts\run.bat
popd
pause