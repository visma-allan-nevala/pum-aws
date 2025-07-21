#!/bin/bash

# run.sh - Run script for pum-aws (Linux/macOS)
# This script automatically sets up the environment if needed and runs the application

set -e  # Exit on any error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$PROJECT_DIR/venv"

echo "=== PUM-AWS Run Script ==="

# Check if virtual environment exists
if [ ! -d "$VENV_DIR" ]; then
    echo "Virtual environment not found. Setting up..."
    echo "Running setup script..."
    "$SCRIPT_DIR/setup.sh"
    echo ""
fi

# Verify virtual environment exists after setup
if [ ! -d "$VENV_DIR" ]; then
    echo "Error: Virtual environment could not be created"
    exit 1
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

# Verify Python application exists
if [ ! -f "$PROJECT_DIR/pum_aws.py" ]; then
    echo "Error: pum_aws.py not found in project directory"
    exit 1
fi

# Run the application with all passed arguments
echo "Running pum-aws..."
echo "Working directory: $PROJECT_DIR"
cd "$PROJECT_DIR"

# Check Python version (requires Python 3.9+)
echo "Checking Python version..."
if ! python -c "import sys; exit(0) if sys.version_info >= (3, 9) else exit(1)" 2>/dev/null; then
    echo "Warning: This application requires Python 3.9 or higher."
    echo "Current Python version: $(python -c "import sys; print('.'.join(map(str, sys.version_info[:3])))" 2>/dev/null || echo "unknown")"
    echo "Please upgrade your Python installation."
    read -p "Press Enter to continue anyway or Ctrl+C to exit..."
fi

echo ""
python pum_aws.py "$@"