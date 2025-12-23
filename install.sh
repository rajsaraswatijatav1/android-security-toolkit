#!/bin/bash

# Android Security Toolkit v2.0 - Installation Script
# This script installs all necessary dependencies and sets up the toolkit

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root. Some operations may require root privileges."
        return 0
    else
        print_status "Running as non-root user."
        return 1
    fi
}

# Function to install system dependencies on Ubuntu/Debian
install_ubuntu_deps() {
    print_status "Installing system dependencies for Ubuntu/Debian..."
    
    # Update package lists
    sudo apt-get update
    
    # Install Android tools and dependencies
    sudo apt-get install -y \
        android-tools-adb \
        android-tools-fastboot \
        nmap \
        tcpdump \
        python3 \
        python3-pip \
        python3-venv \
        git \
        curl \
        wget \
        sqlite3 \
        default-jre \
        default-jdk \
        build-essential \
        libssl-dev \
        libffi-dev
    
    print_success "Ubuntu/Debian dependencies installed"
}

# Function to install system dependencies on macOS
install_macos_deps() {
    print_status "Installing system dependencies for macOS..."
    
    # Check if Homebrew is installed
    if ! command -v brew &> /dev/null; then
        print_status "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    
    # Install dependencies
    brew install \
        android-platform-tools \
        nmap \
        python3 \
        git \
        curl \
        wget \
        sqlite3
    
    print_success "macOS dependencies installed"
}

# Function to install Python dependencies
install_python_deps() {
    print_status "Installing Python dependencies..."
    
    # Create virtual environment if it doesn't exist
    if [[ ! -d "venv" ]]; then
        python3 -m venv venv
        print_success "Created Python virtual environment"
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install requirements
    pip install -r requirements.txt
    
    print_success "Python dependencies installed"
}

# Function to setup directory structure
setup_directories() {
    print_status "Setting up directory structure..."
    
    # Create necessary directories
    directories=(
        "loot"
        "loot/extracted_data"
        "loot/logs"
        "loot/screenshots"
        "loot/recordings"
        "loot/network"
        "loot/apk_analysis"
        "loot/downloads"
        "wordlists/generated"
        "rules/custom"
        "config"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
        print_success "Created directory: $dir"
    done
}

# Function to set permissions
set_permissions() {
    print_status "Setting file permissions..."
    
    # Make main scripts executable
    chmod +x main.py
    chmod +x api_server.py
    chmod +x install.sh
    
    print_success "File permissions set"
}

# Function to check ADB installation
check_adb() {
    print_status "Checking ADB installation..."
    
    if command -v adb &> /dev/null; then
        adb_version=$(adb version)
        print_success "ADB is installed: $adb_version"
    else
        print_error "ADB is not installed or not in PATH"
        return 1
    fi
}

# Function to test ADB connection
test_adb() {
    print_status "Testing ADB connection..."
    
    # Start ADB server
    adb start-server
    
    # List devices
    devices=$(adb devices)
    print_status "Connected devices:"
    echo "$devices"
    
    if [[ $(echo "$devices" | wc -l) -gt 2 ]]; then
        print_success "ADB is working and devices are detected"
    else
        print_warning "No devices detected. Connect an Android device with USB debugging enabled."
    fi
}

# Function to install optional tools
install_optional_tools() {
    print_status "Installing optional tools..."
    
    # Ask user about optional tools
    read -p "Install Frida for dynamic analysis? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        pip install frida-tools
        print_success "Frida installed"
    fi
    
    read -p "Install JADX for APK decompilation? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            # Download JADX
            JADX_VERSION="1.4.7"
            wget -O jadx.zip "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip"
            unzip jadx.zip -d jadx
            sudo mv jadx/bin/* /usr/local/bin/
            rm -rf jadx.zip jadx
            print_success "JADX installed"
        else
            print_warning "JADX installation skipped. Please install manually."
        fi
    fi
}

# Function to create configuration files
create_config() {
    print_status "Creating configuration files..."
    
    # Create default config if it doesn't exist
    if [[ ! -f "config/config.yaml" ]]; then
        cat > config/config.yaml << 'EOF'
# Android Security Toolkit Configuration

# ADB Settings
adb:
  timeout: 30
  retry_attempts: 3
  ports:
    - 5555
    - 5556
    - 5557
    - 5558
    - 5559
    - 5560

# Scanning Settings
scanning:
  thread_count: 8
  timeout: 60
  max_devices: 100
  
# Cracking Settings
cracking:
  max_threads: 16
  timeout: 3600
  wordlists:
    - wordlists/android_pins.txt
    - wordlists/passwords_top1000.txt
    - wordlists/common_patterns.txt

# Logging Settings
logging:
  level: INFO
  file: loot/android_security_toolkit.log
  max_size: 100MB
  backup_count: 5

# API Settings (for api_server.py)
api:
  host: 0.0.0.0
  port: 8000
  workers: 4
  timeout: 300
EOF
        print_success "Created default configuration file"
    fi
}

# Function to display usage instructions
show_usage() {
    print_success "Installation completed successfully!"
    echo
    print_status "Usage Instructions:"
    echo "  Activate virtual environment: source venv/bin/activate"
    echo "  Show help: python main.py --help"
    echo "  Discover devices: python main.py --consent adb-discover"
    echo "  Analyze APK: python main.py --consent analyze-apk app.apk"
    echo "  Interactive shell: python main.py --consent shell"
    echo
    print_status "Connect an Android device with USB debugging enabled to get started."
    echo
    print_warning "IMPORTANT: Always use the --consent flag to confirm authorized use."
    print_warning "Unauthorized access is ILLEGAL."
}

# Main installation function
main() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    ANDROID SECURITY TOOLKIT v2.0                            ║"
    echo "║                         Installation Script                                  ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo
    
    # Check if running as root for some operations
    check_root
    
    # Detect OS
    OS=$(detect_os)
    print_status "Detected OS: $OS"
    
    # Install system dependencies based on OS
    case $OS in
        linux)
            install_ubuntu_deps
            ;;
        macos)
            install_macos_deps
            ;;
        *)
            print_error "Unsupported operating system: $OS"
            exit 1
            ;;
    esac
    
    # Setup directories
    setup_directories
    
    # Install Python dependencies
    install_python_deps
    
    # Set permissions
    set_permissions
    
    # Check ADB
    check_adb
    
    # Test ADB
    test_adb
    
    # Install optional tools
    install_optional_tools
    
    # Create configuration files
    create_config
    
    # Show usage instructions
    show_usage
}

# Run main function
main "$@"