#!/bin/bash

# setup.sh - Setup script for pum-aws (Linux/macOS)
# This script creates a virtual environment and installs dependencies

set -e  # Exit on any error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$PROJECT_DIR/venv"

echo "=== PUM-AWS Setup Script ==="
echo "Project directory: $PROJECT_DIR"
echo "Virtual environment directory: $VENV_DIR"

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is not installed or not in PATH"
    echo "Please install Python 3.6+ and try again"
    exit 1
fi

# Check Python version
python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "Python version: $python_version"

# Create virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
    echo "Virtual environment created successfully"
else
    echo "Virtual environment already exists"
fi

# Activate virtual environment
echo "Activating virtual environment..."
if [ -f "$VENV_DIR/bin/activate" ]; then
    # Unix-style activation
    source "$VENV_DIR/bin/activate"
elif [ -f "$VENV_DIR/Scripts/activate" ]; then
    # Windows-style activation (when running bash on Windows)
    source "$VENV_DIR/Scripts/activate"
else
    echo "Error: Could not find activation script in virtual environment"
    exit 1
fi

# Upgrade pip
echo "Upgrading pip..."
python -m pip install --upgrade pip

# Install dependencies
echo "Installing dependencies from requirements.txt..."
if [ -f "$PROJECT_DIR/requirements.txt" ]; then
    pip install -r "$PROJECT_DIR/requirements.txt"
    echo "Dependencies installed successfully"
else
    echo "Warning: requirements.txt not found"
fi

echo ""
echo "=== Setup Complete ==="
echo "Virtual environment is ready at: $VENV_DIR"
echo "To activate manually: source $VENV_DIR/bin/activate"
echo "To run the application: ./scripts/run.sh"