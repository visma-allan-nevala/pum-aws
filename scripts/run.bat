@echo off
REM run.bat - Run script for pum-aws (Windows)
REM This script automatically sets up the environment if needed and runs the application

setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
set PROJECT_DIR=%SCRIPT_DIR%..
set VENV_DIR=%PROJECT_DIR%\venv

pushd "%PROJECT_DIR%"

echo === PUM-AWS Run Script ===

REM Check if virtual environment exists
if not exist "%VENV_DIR%" (
    echo Virtual environment not found. Setting up...
    echo Running setup script...
    call "%SCRIPT_DIR%\setup.bat"
    echo.
)

REM Verify virtual environment exists after setup
if not exist "%VENV_DIR%" (
    echo Error: Virtual environment could not be created
    pause
    exit /b 1
)

REM Activate virtual environment
echo Activating virtual environment...
call "%VENV_DIR%\Scripts\activate.bat"

REM Verify Python application exists
if not exist "%PROJECT_DIR%\pum_aws.py" (
    echo Error: pum_aws.py not found in project directory
    pause
    exit /b 1
)

REM Run the application with all passed arguments
echo Running pum-aws...
echo Working directory: %PROJECT_DIR%
cd /d "%PROJECT_DIR%"
echo:
python pum_aws.py %*
popd