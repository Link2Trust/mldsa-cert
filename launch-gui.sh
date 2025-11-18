#!/bin/bash
# ML-DSA Certificate Generator GUI Launcher

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 not found. Please install Python 3.7 or later."
    exit 1
fi

# Check if tkinter is available
if ! python3 -c "import tkinter" &> /dev/null; then
    echo "Error: tkinter not found."
    echo ""
    echo "Install tkinter:"
    echo "  macOS:    brew install python-tk"
    echo "  Ubuntu:   sudo apt-get install python3-tk"
    echo "  Fedora:   sudo dnf install python3-tkinter"
    exit 1
fi

# Launch the GUI
echo "Starting ML-DSA Certificate Generator GUI..."
cd "$SCRIPT_DIR"
python3 gui.py
