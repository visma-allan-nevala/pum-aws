# Scripts Summary

This document provides a quick overview of the helper scripts in the `scripts/` directory.

## Setup Scripts

### `setup.sh` (Linux/macOS)
- Creates a Python virtual environment in the `venv` directory
- Installs dependencies from `requirements.txt`
- Provides robust error handling and user feedback
- Checks Python version and availability

### `setup.bat` (Windows)
- Creates a Python virtual environment in the `venv` directory
- Installs dependencies from `requirements.txt`
- Provides robust error handling and user feedback
- Checks Python version and availability

## Run Scripts

### `run.sh` (Linux/macOS)
- Automatically detects if virtual environment exists
- Runs setup script if virtual environment is missing
- Activates virtual environment
- Executes `pum_aws.py` with any provided arguments
- Provides error handling and user feedback

### `run.bat` (Windows)
- Automatically detects if virtual environment exists
- Runs setup script if virtual environment is missing
- Activates virtual environment
- Executes `pum_aws.py` with any provided arguments
- Provides error handling and user feedback

## Usage Examples

### First time setup (optional - run scripts do this automatically):
```bash
# Linux/macOS
./scripts/setup.sh

# Windows
scripts\setup.bat
```

### Running the application:
```bash
# Linux/macOS
./scripts/run.sh

# Windows
scripts\run.bat
```

### Running with arguments:
```bash
# Linux/macOS
./scripts/run.sh --profile test --account 123123123

# Windows
scripts\run.bat --profile test --account 123123123
```

## Features

- **Automatic Setup**: Run scripts automatically detect missing virtual environments and set them up
- **Cross-Platform**: Separate scripts for Windows (.bat) and Linux/macOS (.sh)
- **Error Handling**: Robust error checking and user-friendly messages
- **Argument Passing**: All arguments are passed through to the main Python application
- **Path Independence**: Scripts work regardless of current working directory
