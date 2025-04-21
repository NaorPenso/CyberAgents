#!/bin/bash
# Setup script for the CyberAgents project on macOS and Linux

# Exit immediately if a command exits with a non-zero status.
set -e

# ASCII Art Banner
echo ""
echo " ██████╗██╗   ██╗██████╗ ███████╗██████╗  █████╗  ██████╗ ███████╗███╗   ██╗████████╗███████╗"
echo "██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝██╔════╝"
echo "██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║   ███████╗"
echo "██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║   ╚════██║"
echo "╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   ███████║"
echo " ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝"
echo ""

echo "--- CyberAgents Project Setup ---"

# --- Helper Functions ---
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# --- OS Detection ---
OS="$(uname -s)"
ARCH="$(uname -m)"
PYTHON_CMD="python3" # Default python command
PIP_CMD="pip3"     # Default pip command

echo "Detected OS: ${OS} (${ARCH})"

# --- System Dependency Checks ---
echo "\n--- Checking System Dependencies ---"

# Package manager variables
INSTALL_CMD=""
UPDATE_CMD=""
GIT_PACKAGE="git"
CURL_PACKAGE="curl"
BUILD_ESSENTIAL_PACKAGE="build-essential" # For Linux

if [[ "$OS" == "Linux" ]]; then
  # Check if apt exists (Debian/Ubuntu)
  if command_exists apt; then
    echo "Detected apt package manager."
    UPDATE_CMD="sudo apt-get update"
    INSTALL_CMD="sudo apt-get install -y"
  # Add checks for other Linux package managers like yum/dnf if needed
  # elif command_exists yum; then ...
  else
    echo "ERROR: Unsupported Linux distribution. No known package manager (apt) found."
    exit 1
  fi
elif [[ "$OS" == "Darwin" ]]; then # macOS
  if ! command_exists brew; then
    echo "ERROR: Homebrew ('brew') is required on macOS but was not found."
    echo "Please install Homebrew first by following the instructions at: https://brew.sh/"
    echo "After installing Homebrew, re-run this setup script."
    exit 1 # Exit because Homebrew is missing
  fi
  echo "Detected Homebrew package manager."
  UPDATE_CMD="brew update"
  INSTALL_CMD="brew install"
  GIT_PACKAGE="git"
  CURL_PACKAGE="curl"
  # No direct equivalent for build-essential needed typically via brew dependencies
else
  echo "ERROR: Unsupported Operating System: ${OS}"
  exit 1
fi

# Update package manager cache
# echo "Updating package manager..."
# $UPDATE_CMD

# Check/Install Git
if ! command_exists git; then
  echo "Git not found. Installing Git using ${INSTALL_CMD}..."
  $INSTALL_CMD $GIT_PACKAGE
else
  echo "Git found."
fi

# Check/Install Curl
if ! command_exists curl; then
  echo "Curl not found. Installing Curl using ${INSTALL_CMD}..."
  $INSTALL_CMD $CURL_PACKAGE
else
  echo "Curl found."
fi

# Check/Install Build Essential (Linux only)
if [[ "$OS" == "Linux" ]] && command_exists dpkg; then # Check dpkg exists before using it
  # Check if build-essential is installed using dpkg status check
  if ! dpkg -s ${BUILD_ESSENTIAL_PACKAGE} >/dev/null 2>&1; then
      echo "Build essential tools not found. Installing..."
      $INSTALL_CMD $BUILD_ESSENTIAL_PACKAGE
  else
      echo "Build essential tools found."
  fi
fi


# --- Python Check ---
echo "\n--- Checking Python --- "
MIN_PYTHON_MAJOR=3
MIN_PYTHON_MINOR=11

# Try python3 first, then python
if ! command_exists $PYTHON_CMD; then
    if command_exists python; then
        PYTHON_CMD=python
        PIP_CMD=pip
    else
        echo "ERROR: Python command not found (tried 'python3' and 'python')."
        echo "Please install Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR} or higher and ensure it's in your PATH."
        exit 1
    fi
fi

# Check Python version
PYTHON_VERSION=$($PYTHON_CMD -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

echo "Found Python version: ${PYTHON_VERSION} (using command: ${PYTHON_CMD})"

if [[ "$PYTHON_MAJOR" -lt "$MIN_PYTHON_MAJOR" ]] || ([[ "$PYTHON_MAJOR" -eq "$MIN_PYTHON_MAJOR" ]] && [[ "$PYTHON_MINOR" -lt "$MIN_PYTHON_MINOR" ]]); then
  echo "ERROR: Python version ${PYTHON_VERSION} is too old. Version ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+ is required."
  echo "Please upgrade your Python installation or use a tool like pyenv to manage Python versions."
  exit 1
else
  echo "Python version is sufficient."
fi

# --- Poetry Check & Installation ---
echo "\n--- Checking/Installing Poetry --- "
if ! command_exists poetry; then
    echo "Poetry not found. Installing Poetry..."
    curl -sSL https://install.python-poetry.org | $PYTHON_CMD -
    # Add poetry to PATH for the current script session
    export PATH="$HOME/.local/bin:$PATH"
    echo "Poetry installed. You might need to restart your shell or run 'source \$HOME/.poetry/env' for the change to take effect permanently."
    # Verify
    if ! command_exists poetry; then
        echo "ERROR: Poetry installation failed or it's not in PATH. Please check the output above."
        exit 1
    fi
else
    echo "Poetry found."
fi
poetry --version

# Check Poetry version and install shell plugin if needed for Poetry 2.0.0+
POETRY_VERSION=$(poetry --version | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+')
POETRY_MAJOR=$(echo $POETRY_VERSION | cut -d. -f1)

if [[ "$POETRY_MAJOR" -ge "2" ]]; then
    echo "Poetry 2.0.0+ detected. Installing poetry shell plugin..."
    poetry self add poetry-plugin-shell
else
    echo "Poetry version is less than 2.0.0. Shell plugin not required."
fi

# --- Ollama Setup (Conditional) ---
# Ollama installation and setup will only run if the environment variable
# INSTALL_OLLAMA is set to "true".
# Example: export INSTALL_OLLAMA=true && ./setup.sh
if [[ "${INSTALL_OLLAMA}" == "true" ]]; then
    echo "--- Checking/Installing Ollama & Pulling Model --- "

    # Check/Install Ollama
    if ! command_exists ollama; then
        echo "Ollama not found. Installing Ollama..."
        curl -fsSL https://ollama.com/install.sh | sh
        echo "Ollama installed. It might run as a background service automatically."
        # Verify installation
        if ! command_exists ollama; then
             echo "ERROR: Ollama installation failed. Please check the output above."
             exit 1
        fi
    else
        echo "Ollama found."
    fi
    ollama --version

    # Pull Ollama Model
    echo "Pulling default Ollama model (phi:latest). This might take a while..."
    # Check if Ollama server is running, start if not (best effort)
    if ! pgrep -x ollama > /dev/null; then
        echo "Ollama server not detected, attempting to start it in the background..."
        # Check if user has permissions to write log here, otherwise might fail silently
        nohup ollama serve > ollama_setup.log 2>&1 &
        sleep 5 # Give it a moment
        if ! pgrep -x ollama > /dev/null; then
            echo "Warning: Failed to automatically start Ollama server. Please start it manually ('ollama serve'). Model pull might fail."
        fi
    fi
    # Attempt to pull the model
    ollama pull phi:latest || echo "Warning: Failed to pull Ollama model. Ensure Ollama server is running, INSTALL_OLLAMA is true, and network is available."
else
    echo "--- Skipping Ollama Setup ---"
    echo "Set INSTALL_OLLAMA=true environment variable to install Ollama and pull the model."
fi

# --- Project Setup ---
echo "\n--- Setting up Project Dependencies --- "

# Ensure script is run from the project root (basic check)
if [ ! -f "pyproject.toml" ]; then
    echo "ERROR: Script must be run from the root directory of the CyberAgents project (where pyproject.toml is located)."
    exit 1
fi

echo "Installing Python dependencies using Poetry..."
poetry install --no-interaction --extras test # Install main + test dependencies



# --- Environment File Setup ---
echo "\n--- Setting up Environment Variables --- "
if [ ! -f ".env" ]; then
  echo "Environment file (.env) not found."
  if [ -f ".env.example" ]; then
    echo "Copying .env.example to .env..."
    cp .env.example .env
    echo "IMPORTANT: Please edit the '.env' file and add your necessary API keys (OpenAI, VirusTotal, Shodan)."
  else
    echo "Warning: .env.example not found. Cannot create .env automatically."
    echo "Please create a .env file manually with required API keys."
  fi
else
  echo ".env file already exists. Ensure it contains the required API keys."
fi

echo "\n--- Setup Complete! --- "
echo "You can now explore the project."
echo "To run the main application (example): python main.py \"Analyze example.com\""
echo "To activate the virtual environment manually: poetry shell"
echo "Remember to set your API keys in the .env file."
