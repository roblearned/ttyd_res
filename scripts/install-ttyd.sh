#!/usr/bin/env bash
#
# ttyd Installation and Configuration Script
# Supports: Linux (systemd) and macOS (launchd)
#
# This script will:
#   1. Detect your operating system
#   2. Install ttyd if not present
#   3. Guide you through all configuration options
#   4. Create a named service instance
#
# Usage: ./install-ttyd.sh
#
# Author: Generated for ttyd v1.7.7+
# License: MIT
#

set -e

# =============================================================================
# CONSTANTS AND DEFAULTS
# =============================================================================

SCRIPT_VERSION="1.0.0"
TTYD_DEFAULT_PORT=7681
TTYD_DEFAULT_TERMINAL="xterm-256color"
TTYD_DEFAULT_SIGNAL="SIGHUP"
TTYD_DEFAULT_DEBUG=7
TTYD_DEFAULT_PING_INTERVAL=5
TTYD_DEFAULT_BUFFER_SIZE=4096

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Configuration storage
declare -A CONFIG

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

print_header() {
    echo -e "\n${BLUE}${BOLD}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}${BOLD}  $1${NC}"
    echo -e "${BLUE}${BOLD}════════════════════════════════════════════════════════════════${NC}\n"
}

print_section() {
    echo -e "\n${CYAN}${BOLD}── $1 ──${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

confirm() {
    local prompt="$1"
    local default="${2:-n}"
    local response

    if [[ "$default" == "y" ]]; then
        prompt="$prompt [Y/n]: "
    else
        prompt="$prompt [y/N]: "
    fi

    read -r -p "$prompt" response
    response="${response:-$default}"
    [[ "$response" =~ ^[Yy]$ ]]
}

prompt_input() {
    local prompt="$1"
    local default="$2"
    local var_name="$3"
    local response

    if [[ -n "$default" ]]; then
        read -r -p "$prompt [$default]: " response
        response="${response:-$default}"
    else
        read -r -p "$prompt: " response
    fi

    CONFIG["$var_name"]="$response"
}

prompt_password() {
    local prompt="$1"
    local var_name="$2"
    local response

    read -r -s -p "$prompt: " response
    echo
    CONFIG["$var_name"]="$response"
}

prompt_number() {
    local prompt="$1"
    local default="$2"
    local var_name="$3"
    local min="${4:-0}"
    local max="${5:-65535}"
    local response

    while true; do
        read -r -p "$prompt [$default]: " response
        response="${response:-$default}"

        if [[ "$response" =~ ^[0-9]+$ ]] && [[ "$response" -ge "$min" ]] && [[ "$response" -le "$max" ]]; then
            CONFIG["$var_name"]="$response"
            break
        else
            print_error "Please enter a number between $min and $max"
        fi
    done
}

prompt_choice() {
    local prompt="$1"
    local var_name="$2"
    shift 2
    local choices=("$@")
    local i=1

    echo "$prompt"
    for choice in "${choices[@]}"; do
        echo "  $i) $choice"
        ((i++))
    done

    while true; do
        read -r -p "Enter choice (1-${#choices[@]}): " response
        if [[ "$response" =~ ^[0-9]+$ ]] && [[ "$response" -ge 1 ]] && [[ "$response" -le "${#choices[@]}" ]]; then
            CONFIG["$var_name"]="${choices[$((response-1))]}"
            break
        else
            print_error "Please enter a number between 1 and ${#choices[@]}"
        fi
    done
}

# =============================================================================
# SYSTEM DETECTION
# =============================================================================

detect_os() {
    local os=""
    local init_system=""

    case "$(uname -s)" in
        Linux*)
            os="linux"
            # Detect init system
            if command -v systemctl &> /dev/null && [[ -d /run/systemd/system ]]; then
                init_system="systemd"
            elif command -v rc-service &> /dev/null; then
                init_system="openrc"
            elif [[ -f /etc/init.d/cron ]]; then
                init_system="sysvinit"
            else
                init_system="unknown"
            fi
            ;;
        Darwin*)
            os="macos"
            init_system="launchd"
            ;;
        MINGW*|MSYS*|CYGWIN*)
            print_error "This script does not support Windows directly."
            print_info "Please use install-ttyd.ps1 for Windows systems."
            exit 1
            ;;
        *)
            os="unknown"
            init_system="unknown"
            ;;
    esac

    CONFIG["os"]="$os"
    CONFIG["init_system"]="$init_system"

    print_info "Detected OS: $os"
    print_info "Init system: $init_system"
}

detect_architecture() {
    local arch=""

    case "$(uname -m)" in
        x86_64|amd64)
            arch="x86_64"
            ;;
        i386|i686)
            arch="i686"
            ;;
        armv7l|armhf)
            arch="armhf"
            ;;
        aarch64|arm64)
            arch="aarch64"
            ;;
        mips)
            arch="mips"
            ;;
        mipsel)
            arch="mipsel"
            ;;
        *)
            arch="$(uname -m)"
            ;;
    esac

    CONFIG["arch"]="$arch"
    print_info "Architecture: $arch"
}

check_dependencies() {
    print_section "Checking Dependencies"

    local missing_deps=()

    # Check for essential commands
    local deps=("curl" "tar")

    for dep in "${deps[@]}"; do
        if command -v "$dep" &> /dev/null; then
            print_success "$dep is installed"
        else
            print_warning "$dep is not installed"
            missing_deps+=("$dep")
        fi
    done

    # Check for ttyd
    if command -v ttyd &> /dev/null; then
        local ttyd_version
        ttyd_version=$(ttyd --version 2>&1 | head -n1)
        print_success "ttyd is installed: $ttyd_version"
        CONFIG["ttyd_installed"]="true"
        CONFIG["ttyd_path"]=$(command -v ttyd)
    else
        print_warning "ttyd is not installed"
        CONFIG["ttyd_installed"]="false"
    fi

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        print_error "Missing required dependencies: ${missing_deps[*]}"
        print_info "Please install them before continuing."
        exit 1
    fi
}

# =============================================================================
# INSTALLATION FUNCTIONS
# =============================================================================

install_ttyd_linux() {
    print_section "Installing ttyd on Linux"

    local arch="${CONFIG["arch"]}"
    local install_method=""

    echo "Choose installation method:"
    echo "  1) Download pre-built binary (recommended)"
    echo "  2) Install via snap (if available)"
    echo "  3) Build from source"
    echo "  4) Skip installation (ttyd already in PATH)"

    read -r -p "Enter choice (1-4): " install_method

    case "$install_method" in
        1)
            install_ttyd_binary_linux
            ;;
        2)
            install_ttyd_snap
            ;;
        3)
            install_ttyd_source
            ;;
        4)
            if [[ "${CONFIG["ttyd_installed"]}" != "true" ]]; then
                print_error "ttyd is not in PATH. Please install it first."
                exit 1
            fi
            ;;
        *)
            print_error "Invalid choice"
            exit 1
            ;;
    esac
}

install_ttyd_binary_linux() {
    local arch="${CONFIG["arch"]}"
    local download_url=""
    local temp_dir
    temp_dir=$(mktemp -d)

    # Map architecture to GitHub release binary name
    case "$arch" in
        x86_64)
            download_url="https://github.com/tsl0922/ttyd/releases/latest/download/ttyd.x86_64"
            ;;
        i686)
            download_url="https://github.com/tsl0922/ttyd/releases/latest/download/ttyd.i686"
            ;;
        armhf)
            download_url="https://github.com/tsl0922/ttyd/releases/latest/download/ttyd.armhf"
            ;;
        aarch64)
            download_url="https://github.com/tsl0922/ttyd/releases/latest/download/ttyd.aarch64"
            ;;
        mips)
            download_url="https://github.com/tsl0922/ttyd/releases/latest/download/ttyd.mips"
            ;;
        mipsel)
            download_url="https://github.com/tsl0922/ttyd/releases/latest/download/ttyd.mipsel"
            ;;
        *)
            print_error "No pre-built binary available for architecture: $arch"
            print_info "Please build from source instead."
            exit 1
            ;;
    esac

    print_info "Downloading ttyd from: $download_url"

    if curl -L -o "$temp_dir/ttyd" "$download_url"; then
        chmod +x "$temp_dir/ttyd"

        local install_path="/usr/local/bin/ttyd"
        prompt_input "Install path" "$install_path" "install_path"
        install_path="${CONFIG["install_path"]}"

        if sudo mv "$temp_dir/ttyd" "$install_path"; then
            print_success "ttyd installed to $install_path"
            CONFIG["ttyd_path"]="$install_path"
            CONFIG["ttyd_installed"]="true"
        else
            print_error "Failed to install ttyd"
            rm -rf "$temp_dir"
            exit 1
        fi
    else
        print_error "Failed to download ttyd"
        rm -rf "$temp_dir"
        exit 1
    fi

    rm -rf "$temp_dir"
}

install_ttyd_snap() {
    if ! command -v snap &> /dev/null; then
        print_error "snap is not installed on this system"
        exit 1
    fi

    print_info "Installing ttyd via snap..."
    if sudo snap install ttyd --classic; then
        print_success "ttyd installed via snap"
        CONFIG["ttyd_path"]="/snap/bin/ttyd"
        CONFIG["ttyd_installed"]="true"
    else
        print_error "Failed to install ttyd via snap"
        exit 1
    fi
}

install_ttyd_source() {
    print_info "Building ttyd from source..."

    # Check build dependencies
    local build_deps=("cmake" "gcc" "g++" "make" "pkg-config")
    local missing_build_deps=()

    for dep in "${build_deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_build_deps+=("$dep")
        fi
    done

    if [[ ${#missing_build_deps[@]} -gt 0 ]]; then
        print_error "Missing build dependencies: ${missing_build_deps[*]}"
        print_info "On Debian/Ubuntu: sudo apt install build-essential cmake libjson-c-dev libwebsockets-dev"
        print_info "On Fedora/RHEL: sudo dnf install cmake gcc gcc-c++ json-c-devel libwebsockets-devel"
        exit 1
    fi

    local source_dir="${PWD}"
    local build_dir="${source_dir}/build"

    mkdir -p "$build_dir"
    cd "$build_dir"

    print_info "Running cmake..."
    cmake ..

    print_info "Building..."
    make -j"$(nproc)"

    print_info "Installing..."
    sudo make install

    cd "$source_dir"

    print_success "ttyd built and installed from source"
    CONFIG["ttyd_path"]="/usr/local/bin/ttyd"
    CONFIG["ttyd_installed"]="true"
}

install_ttyd_macos() {
    print_section "Installing ttyd on macOS"

    echo "Choose installation method:"
    echo "  1) Install via Homebrew (recommended)"
    echo "  2) Install via MacPorts"
    echo "  3) Download pre-built binary"
    echo "  4) Skip installation (ttyd already in PATH)"

    read -r -p "Enter choice (1-4): " install_method

    case "$install_method" in
        1)
            if ! command -v brew &> /dev/null; then
                print_error "Homebrew is not installed"
                print_info "Install from: https://brew.sh"
                exit 1
            fi
            print_info "Installing ttyd via Homebrew..."
            brew install ttyd
            CONFIG["ttyd_path"]="$(brew --prefix)/bin/ttyd"
            CONFIG["ttyd_installed"]="true"
            print_success "ttyd installed via Homebrew"
            ;;
        2)
            if ! command -v port &> /dev/null; then
                print_error "MacPorts is not installed"
                exit 1
            fi
            print_info "Installing ttyd via MacPorts..."
            sudo port install ttyd
            CONFIG["ttyd_path"]="/opt/local/bin/ttyd"
            CONFIG["ttyd_installed"]="true"
            print_success "ttyd installed via MacPorts"
            ;;
        3)
            install_ttyd_binary_macos
            ;;
        4)
            if [[ "${CONFIG["ttyd_installed"]}" != "true" ]]; then
                print_error "ttyd is not in PATH. Please install it first."
                exit 1
            fi
            ;;
        *)
            print_error "Invalid choice"
            exit 1
            ;;
    esac
}

install_ttyd_binary_macos() {
    local arch="${CONFIG["arch"]}"
    local download_url=""
    local temp_dir
    temp_dir=$(mktemp -d)

    # Determine the correct binary for macOS
    if [[ "$arch" == "aarch64" ]] || [[ "$arch" == "arm64" ]]; then
        # Apple Silicon - there might not be a specific binary, try universal
        print_warning "Apple Silicon detected. Attempting to download binary..."
    fi

    # Try to get the latest release for macOS
    download_url="https://github.com/tsl0922/ttyd/releases/latest/download/ttyd.x86_64"

    print_info "Downloading ttyd from: $download_url"
    print_warning "Note: You may need to use Homebrew for native Apple Silicon support"

    if curl -L -o "$temp_dir/ttyd" "$download_url"; then
        chmod +x "$temp_dir/ttyd"

        local install_path="/usr/local/bin/ttyd"
        prompt_input "Install path" "$install_path" "install_path"
        install_path="${CONFIG["install_path"]}"

        if sudo mv "$temp_dir/ttyd" "$install_path"; then
            print_success "ttyd installed to $install_path"
            CONFIG["ttyd_path"]="$install_path"
            CONFIG["ttyd_installed"]="true"
        else
            print_error "Failed to install ttyd"
            rm -rf "$temp_dir"
            exit 1
        fi
    else
        print_error "Failed to download ttyd"
        rm -rf "$temp_dir"
        exit 1
    fi

    rm -rf "$temp_dir"
}

# =============================================================================
# CONFIGURATION FUNCTIONS
# =============================================================================

configure_instance_name() {
    print_section "Instance Configuration"

    echo "Enter a unique name for this ttyd instance."
    echo "This will be used for the service name and configuration."
    echo "Example: web-shell, admin-terminal, dev-console"
    echo

    while true; do
        prompt_input "Instance name" "ttyd-default" "instance_name"

        local name="${CONFIG["instance_name"]}"

        # Validate instance name (alphanumeric, hyphens, underscores only)
        if [[ "$name" =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ ]]; then
            print_success "Instance name: $name"
            break
        else
            print_error "Invalid name. Use only letters, numbers, hyphens, and underscores. Must start with a letter."
        fi
    done
}

configure_command() {
    print_section "Command Configuration"

    echo "Specify the command/shell to run in the terminal."
    echo "This is what users will see when they connect."
    echo
    echo "Examples:"
    echo "  - bash (default shell)"
    echo "  - /bin/zsh (Z shell)"
    echo "  - /usr/bin/htop (system monitor)"
    echo "  - python3 (Python REPL)"
    echo "  - /custom/app --arg1 --arg2"
    echo

    local default_shell="${SHELL:-/bin/bash}"
    prompt_input "Command to run" "$default_shell" "command"

    # Ask for additional arguments
    if confirm "Do you want to pass arguments to the command?" "n"; then
        prompt_input "Command arguments (space-separated)" "" "command_args"
    fi
}

configure_network() {
    print_section "Network Configuration"

    # Port
    echo "Port to listen on (0 for random port, default: $TTYD_DEFAULT_PORT)"
    prompt_number "Port" "$TTYD_DEFAULT_PORT" "port" 0 65535

    # Interface binding
    echo
    if confirm "Bind to a specific network interface?" "n"; then
        echo "Enter interface name (e.g., eth0, lo) or UNIX socket path (e.g., /var/run/ttyd.sock)"
        prompt_input "Interface/Socket" "" "interface"

        # UNIX socket ownership
        if [[ "${CONFIG["interface"]}" == /* ]]; then
            echo
            if confirm "Set UNIX socket ownership?" "n"; then
                prompt_input "Socket owner (format: user:group)" "" "socket_owner"
            fi
        fi
    fi

    # IPv6
    echo
    if confirm "Enable IPv6 support?" "n"; then
        CONFIG["ipv6"]="true"
    else
        CONFIG["ipv6"]="false"
    fi
}

configure_authentication() {
    print_section "Authentication Configuration"

    echo "Authentication protects your terminal from unauthorized access."
    echo
    echo "Options:"
    echo "  1) No authentication (not recommended for public access)"
    echo "  2) Basic authentication (username:password)"
    echo "  3) Proxy authentication header (for reverse proxy setups)"
    echo

    read -r -p "Choose authentication method (1-3) [1]: " auth_choice
    auth_choice="${auth_choice:-1}"

    case "$auth_choice" in
        1)
            CONFIG["auth_type"]="none"
            print_warning "No authentication configured. Terminal will be publicly accessible!"
            ;;
        2)
            CONFIG["auth_type"]="basic"
            prompt_input "Username" "" "auth_username"
            prompt_password "Password" "auth_password"

            if [[ -z "${CONFIG["auth_username"]}" ]] || [[ -z "${CONFIG["auth_password"]}" ]]; then
                print_error "Username and password cannot be empty"
                exit 1
            fi
            print_success "Basic authentication configured"
            ;;
        3)
            CONFIG["auth_type"]="header"
            echo "Enter the HTTP header name that contains the authenticated user"
            echo "Examples: X-Authenticated-User, X-Auth-Request-User, Remote-User"
            prompt_input "Auth header name" "X-Authenticated-User" "auth_header"
            print_success "Proxy authentication configured via header: ${CONFIG["auth_header"]}"
            ;;
        *)
            print_error "Invalid choice"
            exit 1
            ;;
    esac
}

configure_ssl() {
    print_section "SSL/TLS Configuration"

    echo "SSL/TLS encrypts the connection between clients and the server."
    echo

    if confirm "Enable SSL/TLS?" "n"; then
        CONFIG["ssl"]="true"

        echo
        echo "Enter paths to your SSL certificate files:"

        while true; do
            prompt_input "SSL certificate file path" "" "ssl_cert"
            if [[ -f "${CONFIG["ssl_cert"]}" ]]; then
                print_success "Certificate file found"
                break
            else
                print_error "File not found: ${CONFIG["ssl_cert"]}"
            fi
        done

        while true; do
            prompt_input "SSL private key file path" "" "ssl_key"
            if [[ -f "${CONFIG["ssl_key"]}" ]]; then
                print_success "Key file found"
                break
            else
                print_error "File not found: ${CONFIG["ssl_key"]}"
            fi
        done

        if confirm "Enable client certificate verification?" "n"; then
            while true; do
                prompt_input "CA certificate file path" "" "ssl_ca"
                if [[ -f "${CONFIG["ssl_ca"]}" ]]; then
                    print_success "CA certificate file found"
                    break
                else
                    print_error "File not found: ${CONFIG["ssl_ca"]}"
                fi
            done
        fi
    else
        CONFIG["ssl"]="false"
    fi
}

configure_process() {
    print_section "Process Configuration"

    # User/Group ID
    echo "Process ownership (leave empty to run as current user)"
    if confirm "Run command as a different user?" "n"; then
        prompt_input "User ID (numeric)" "" "uid"
        prompt_input "Group ID (numeric)" "" "gid"
    fi

    # Working directory
    echo
    if confirm "Set a specific working directory?" "n"; then
        while true; do
            prompt_input "Working directory" "$HOME" "cwd"
            if [[ -d "${CONFIG["cwd"]}" ]]; then
                print_success "Working directory: ${CONFIG["cwd"]}"
                break
            else
                print_error "Directory not found: ${CONFIG["cwd"]}"
            fi
        done
    fi

    # Signal
    echo
    echo "Signal to send to the process when closing the terminal"
    echo "Common signals: SIGHUP (1), SIGTERM (15), SIGKILL (9), SIGINT (2)"
    prompt_input "Signal" "$TTYD_DEFAULT_SIGNAL" "signal"
}

configure_terminal() {
    print_section "Terminal Configuration"

    # Terminal type
    echo "Terminal type reported to the shell"
    echo "Common types: xterm-256color, xterm, vt100, screen"
    prompt_input "Terminal type" "$TTYD_DEFAULT_TERMINAL" "terminal_type"

    # Custom index
    echo
    if confirm "Use a custom index.html file?" "n"; then
        while true; do
            prompt_input "Path to custom index.html" "" "custom_index"
            if [[ -f "${CONFIG["custom_index"]}" ]]; then
                print_success "Custom index file found"
                break
            else
                print_error "File not found: ${CONFIG["custom_index"]}"
            fi
        done
    fi

    # Base path
    echo
    if confirm "Set a base path (for reverse proxy)?" "n"; then
        prompt_input "Base path" "/" "base_path"
    fi
}

configure_access() {
    print_section "Access Control Configuration"

    # Writable
    echo "By default, ttyd runs in read-only mode (clients cannot type)."
    if confirm "Allow clients to write to the terminal?" "y"; then
        CONFIG["writable"]="true"
        print_info "Terminal will be writable"
    else
        CONFIG["writable"]="false"
        print_info "Terminal will be read-only"
    fi

    # URL arguments
    echo
    if confirm "Allow command-line arguments from URL? (e.g., ?arg=foo&arg=bar)" "n"; then
        CONFIG["url_args"]="true"
        print_warning "URL arguments enabled - be careful with this option!"
    else
        CONFIG["url_args"]="false"
    fi
}

configure_clients() {
    print_section "Client Management Configuration"

    # Max clients
    echo "Maximum number of concurrent clients (0 = unlimited)"
    prompt_number "Max clients" "0" "max_clients" 0 10000

    # Once mode
    echo
    if confirm "Accept only one client and exit on disconnect? (once mode)" "n"; then
        CONFIG["once"]="true"
    else
        CONFIG["once"]="false"
    fi

    # Exit on no connections
    if [[ "${CONFIG["once"]}" != "true" ]]; then
        echo
        if confirm "Exit when all clients disconnect?" "n"; then
            CONFIG["exit_no_conn"]="true"
        else
            CONFIG["exit_no_conn"]="false"
        fi
    fi

    # Check origin
    echo
    if confirm "Check WebSocket origin (reject cross-origin connections)?" "n"; then
        CONFIG["check_origin"]="true"
    else
        CONFIG["check_origin"]="false"
    fi

    # Ping interval
    echo
    echo "WebSocket ping interval in seconds (for connection keepalive)"
    prompt_number "Ping interval" "$TTYD_DEFAULT_PING_INTERVAL" "ping_interval" 0 3600
}

configure_client_options() {
    print_section "Client-Side Options (xterm.js)"

    echo "These options customize the terminal appearance and behavior for clients."
    echo

    declare -a client_opts

    # Font size
    if confirm "Set custom font size?" "n"; then
        prompt_number "Font size (pixels)" "14" "client_font_size" 8 72
        client_opts+=("fontSize=${CONFIG["client_font_size"]}")
    fi

    # Renderer
    echo
    echo "Renderer type:"
    echo "  1) WebGL (default, faster)"
    echo "  2) Canvas (more compatible)"
    read -r -p "Choose renderer (1-2) [1]: " renderer_choice
    if [[ "$renderer_choice" == "2" ]]; then
        client_opts+=("rendererType=canvas")
    fi

    # Cursor style
    echo
    echo "Cursor style:"
    echo "  1) Block (default)"
    echo "  2) Underline"
    echo "  3) Bar"
    read -r -p "Choose cursor style (1-3) [1]: " cursor_choice
    case "$cursor_choice" in
        2) client_opts+=("cursorStyle=underline") ;;
        3) client_opts+=("cursorStyle=bar") ;;
    esac

    # Special features
    echo
    if confirm "Enable ZMODEM file transfer? (requires lrzsz)" "n"; then
        client_opts+=("enableZmodem=true")
    fi

    if confirm "Enable trzsz file transfer?" "n"; then
        client_opts+=("enableTrzsz=true")
    fi

    if confirm "Enable Sixel image support?" "n"; then
        client_opts+=("enableSixel=true")
    fi

    # Alerts
    if confirm "Disable page leave alert?" "n"; then
        client_opts+=("disableLeaveAlert=true")
    fi

    if confirm "Disable resize overlay?" "n"; then
        client_opts+=("disableResizeOverlay=true")
    fi

    if confirm "Disable auto-reconnect?" "n"; then
        client_opts+=("disableReconnect=true")
    fi

    # Fixed title
    if confirm "Set fixed browser window title?" "n"; then
        prompt_input "Window title" "" "client_title"
        if [[ -n "${CONFIG["client_title"]}" ]]; then
            client_opts+=("titleFixed=${CONFIG["client_title"]}")
        fi
    fi

    # Store client options
    CONFIG["client_options"]="${client_opts[*]}"
}

configure_performance() {
    print_section "Performance Configuration"

    # Debug level
    echo "Debug/log level (bitmask: 1=ERR, 2=WARN, 4=NOTICE)"
    echo "  7 = All messages (ERR + WARN + NOTICE)"
    echo "  3 = Errors and warnings only"
    echo "  1 = Errors only"
    prompt_number "Debug level" "$TTYD_DEFAULT_DEBUG" "debug_level" 0 255

    # Buffer size
    echo
    echo "Server buffer size (larger values can improve file transfer throughput)"
    prompt_number "Buffer size (bytes)" "$TTYD_DEFAULT_BUFFER_SIZE" "buffer_size" 1024 1048576
}

configure_browser() {
    print_section "Browser Options"

    if confirm "Open terminal in browser automatically on start?" "n"; then
        CONFIG["browser"]="true"
    else
        CONFIG["browser"]="false"
    fi
}

# =============================================================================
# COMMAND BUILDING
# =============================================================================

build_ttyd_command() {
    local cmd="${CONFIG["ttyd_path"]:-ttyd}"
    local args=()

    # Network options
    [[ -n "${CONFIG["port"]}" ]] && args+=("-p" "${CONFIG["port"]}")
    [[ -n "${CONFIG["interface"]}" ]] && args+=("-i" "${CONFIG["interface"]}")
    [[ -n "${CONFIG["socket_owner"]}" ]] && args+=("-U" "${CONFIG["socket_owner"]}")
    [[ "${CONFIG["ipv6"]}" == "true" ]] && args+=("-6")

    # Authentication
    if [[ "${CONFIG["auth_type"]}" == "basic" ]]; then
        args+=("-c" "${CONFIG["auth_username"]}:${CONFIG["auth_password"]}")
    elif [[ "${CONFIG["auth_type"]}" == "header" ]]; then
        args+=("-H" "${CONFIG["auth_header"]}")
    fi

    # SSL
    if [[ "${CONFIG["ssl"]}" == "true" ]]; then
        args+=("-S")
        args+=("-C" "${CONFIG["ssl_cert"]}")
        args+=("-K" "${CONFIG["ssl_key"]}")
        [[ -n "${CONFIG["ssl_ca"]}" ]] && args+=("-A" "${CONFIG["ssl_ca"]}")
    fi

    # Process options
    [[ -n "${CONFIG["uid"]}" ]] && args+=("-u" "${CONFIG["uid"]}")
    [[ -n "${CONFIG["gid"]}" ]] && args+=("-g" "${CONFIG["gid"]}")
    [[ -n "${CONFIG["cwd"]}" ]] && args+=("-w" "${CONFIG["cwd"]}")
    [[ -n "${CONFIG["signal"]}" ]] && args+=("-s" "${CONFIG["signal"]}")

    # Terminal options
    [[ -n "${CONFIG["terminal_type"]}" ]] && args+=("-T" "${CONFIG["terminal_type"]}")
    [[ -n "${CONFIG["custom_index"]}" ]] && args+=("-I" "${CONFIG["custom_index"]}")
    [[ -n "${CONFIG["base_path"]}" ]] && args+=("-b" "${CONFIG["base_path"]}")

    # Access control
    [[ "${CONFIG["writable"]}" == "true" ]] && args+=("-W")
    [[ "${CONFIG["url_args"]}" == "true" ]] && args+=("-a")

    # Client management
    [[ -n "${CONFIG["max_clients"]}" ]] && [[ "${CONFIG["max_clients"]}" != "0" ]] && args+=("-m" "${CONFIG["max_clients"]}")
    [[ "${CONFIG["once"]}" == "true" ]] && args+=("-o")
    [[ "${CONFIG["exit_no_conn"]}" == "true" ]] && args+=("-q")
    [[ "${CONFIG["check_origin"]}" == "true" ]] && args+=("-O")
    [[ -n "${CONFIG["ping_interval"]}" ]] && args+=("-P" "${CONFIG["ping_interval"]}")

    # Client options
    if [[ -n "${CONFIG["client_options"]}" ]]; then
        for opt in ${CONFIG["client_options"]}; do
            args+=("-t" "$opt")
        done
    fi

    # Performance
    [[ -n "${CONFIG["debug_level"]}" ]] && args+=("-d" "${CONFIG["debug_level"]}")
    [[ -n "${CONFIG["buffer_size"]}" ]] && args+=("-f" "${CONFIG["buffer_size"]}")

    # Browser
    [[ "${CONFIG["browser"]}" == "true" ]] && args+=("-B")

    # Command
    args+=("${CONFIG["command"]}")
    [[ -n "${CONFIG["command_args"]}" ]] && args+=(${CONFIG["command_args"]})

    CONFIG["ttyd_full_command"]="$cmd ${args[*]}"
    CONFIG["ttyd_args"]="${args[*]}"
}

# =============================================================================
# SERVICE CREATION
# =============================================================================

create_systemd_service() {
    local instance_name="${CONFIG["instance_name"]}"
    local service_name="ttyd-${instance_name}"
    local service_file="/etc/systemd/system/${service_name}.service"
    local ttyd_path="${CONFIG["ttyd_path"]:-$(command -v ttyd)}"

    print_section "Creating systemd Service"

    # Build command arguments (without the ttyd binary itself)
    local exec_args="${CONFIG["ttyd_args"]}"

    # Create service file content
    local service_content="[Unit]
Description=ttyd terminal: ${instance_name}
After=network.target
Documentation=https://github.com/tsl0922/ttyd

[Service]
Type=simple
ExecStart=${ttyd_path} ${exec_args}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening (optional, adjust as needed)
# NoNewPrivileges=true
# ProtectSystem=strict
# ProtectHome=read-only
# PrivateTmp=true

[Install]
WantedBy=multi-user.target
"

    print_info "Creating service file: $service_file"

    # Write service file
    echo "$service_content" | sudo tee "$service_file" > /dev/null

    print_success "Service file created"

    # Reload systemd
    print_info "Reloading systemd daemon..."
    sudo systemctl daemon-reload

    print_success "systemd daemon reloaded"

    # Ask to enable and start
    echo
    if confirm "Enable service to start on boot?" "y"; then
        sudo systemctl enable "$service_name"
        print_success "Service enabled"
    fi

    if confirm "Start the service now?" "y"; then
        sudo systemctl start "$service_name"
        sleep 2

        if systemctl is-active --quiet "$service_name"; then
            print_success "Service started successfully"
        else
            print_error "Service failed to start. Check logs with: journalctl -u $service_name"
        fi
    fi

    # Print management commands
    echo
    print_section "Service Management Commands"
    echo "  Start:   sudo systemctl start $service_name"
    echo "  Stop:    sudo systemctl stop $service_name"
    echo "  Restart: sudo systemctl restart $service_name"
    echo "  Status:  sudo systemctl status $service_name"
    echo "  Logs:    journalctl -u $service_name -f"
    echo "  Disable: sudo systemctl disable $service_name"
}

create_launchd_service() {
    local instance_name="${CONFIG["instance_name"]}"
    local service_name="com.ttyd.${instance_name}"
    local plist_file="$HOME/Library/LaunchAgents/${service_name}.plist"
    local ttyd_path="${CONFIG["ttyd_path"]:-$(command -v ttyd)}"

    print_section "Creating launchd Service"

    # Build program arguments array for plist
    local program_args="<string>${ttyd_path}</string>"

    # Parse arguments
    for arg in ${CONFIG["ttyd_args"]}; do
        program_args+="\n        <string>${arg}</string>"
    done

    # Create plist content
    local plist_content="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
    <key>Label</key>
    <string>${service_name}</string>
    <key>ProgramArguments</key>
    <array>
        $(echo -e "$program_args")
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/ttyd-${instance_name}.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/ttyd-${instance_name}.err</string>
</dict>
</plist>"

    # Create LaunchAgents directory if needed
    mkdir -p "$HOME/Library/LaunchAgents"

    print_info "Creating plist file: $plist_file"

    # Write plist file
    echo "$plist_content" > "$plist_file"

    print_success "Plist file created"

    # Load service
    if confirm "Load the service now?" "y"; then
        launchctl load "$plist_file" 2>/dev/null || true
        launchctl start "$service_name" 2>/dev/null || true

        sleep 2

        if launchctl list | grep -q "$service_name"; then
            print_success "Service loaded successfully"
        else
            print_warning "Service may not have loaded correctly. Check logs."
        fi
    fi

    # Print management commands
    echo
    print_section "Service Management Commands"
    echo "  Load:    launchctl load $plist_file"
    echo "  Unload:  launchctl unload $plist_file"
    echo "  Start:   launchctl start $service_name"
    echo "  Stop:    launchctl stop $service_name"
    echo "  Status:  launchctl list | grep ttyd"
    echo "  Logs:    tail -f /tmp/ttyd-${instance_name}.log"
}

create_sysvinit_service() {
    local instance_name="${CONFIG["instance_name"]}"
    local service_name="ttyd-${instance_name}"
    local init_script="/etc/init.d/${service_name}"
    local ttyd_path="${CONFIG["ttyd_path"]:-$(command -v ttyd)}"
    local pid_file="/var/run/${service_name}.pid"

    print_section "Creating SysVinit Service"

    local script_content="#!/bin/sh
### BEGIN INIT INFO
# Provides:          ${service_name}
# Required-Start:    \$network \$remote_fs
# Required-Stop:     \$network \$remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: ttyd terminal: ${instance_name}
# Description:       Web-based terminal sharing service
### END INIT INFO

DAEMON=\"${ttyd_path}\"
DAEMON_ARGS=\"${CONFIG["ttyd_args"]}\"
PIDFILE=\"${pid_file}\"
NAME=\"${service_name}\"

case \"\$1\" in
    start)
        echo \"Starting \$NAME...\"
        start-stop-daemon --start --background --make-pidfile --pidfile \$PIDFILE --exec \$DAEMON -- \$DAEMON_ARGS
        ;;
    stop)
        echo \"Stopping \$NAME...\"
        start-stop-daemon --stop --pidfile \$PIDFILE --retry 10
        rm -f \$PIDFILE
        ;;
    restart)
        \$0 stop
        \$0 start
        ;;
    status)
        if [ -f \$PIDFILE ] && kill -0 \$(cat \$PIDFILE) 2>/dev/null; then
            echo \"\$NAME is running (PID: \$(cat \$PIDFILE))\"
        else
            echo \"\$NAME is not running\"
            exit 1
        fi
        ;;
    *)
        echo \"Usage: \$0 {start|stop|restart|status}\"
        exit 1
        ;;
esac

exit 0
"

    print_info "Creating init script: $init_script"

    echo "$script_content" | sudo tee "$init_script" > /dev/null
    sudo chmod +x "$init_script"

    print_success "Init script created"

    # Update rc.d links
    if command -v update-rc.d &> /dev/null; then
        if confirm "Enable service to start on boot?" "y"; then
            sudo update-rc.d "$service_name" defaults
            print_success "Service enabled"
        fi
    fi

    if confirm "Start the service now?" "y"; then
        sudo "$init_script" start
        print_success "Service start requested"
    fi

    # Print management commands
    echo
    print_section "Service Management Commands"
    echo "  Start:   sudo $init_script start"
    echo "  Stop:    sudo $init_script stop"
    echo "  Restart: sudo $init_script restart"
    echo "  Status:  sudo $init_script status"
}

create_service() {
    local init_system="${CONFIG["init_system"]}"

    case "$init_system" in
        systemd)
            create_systemd_service
            ;;
        launchd)
            create_launchd_service
            ;;
        sysvinit|openrc)
            create_sysvinit_service
            ;;
        *)
            print_warning "Unknown init system: $init_system"
            print_info "Manual service configuration required"
            print_section "Generated Command"
            echo "${CONFIG["ttyd_full_command"]}"
            ;;
    esac
}

# =============================================================================
# CONFIGURATION SUMMARY
# =============================================================================

show_configuration_summary() {
    print_section "Configuration Summary"

    echo "Instance Name: ${CONFIG["instance_name"]}"
    echo "Command:       ${CONFIG["command"]} ${CONFIG["command_args"]}"
    echo "Port:          ${CONFIG["port"]}"
    echo "Writable:      ${CONFIG["writable"]}"
    echo "SSL:           ${CONFIG["ssl"]}"
    echo "Auth Type:     ${CONFIG["auth_type"]}"
    echo
    echo "Full Command:"
    echo "  ${CONFIG["ttyd_full_command"]}"
    echo
}

save_configuration() {
    local instance_name="${CONFIG["instance_name"]}"
    local config_dir="$HOME/.config/ttyd"
    local config_file="${config_dir}/${instance_name}.conf"

    mkdir -p "$config_dir"

    print_info "Saving configuration to: $config_file"

    # Save configuration
    {
        echo "# ttyd configuration for instance: ${instance_name}"
        echo "# Generated on: $(date)"
        echo ""
        for key in "${!CONFIG[@]}"; do
            # Don't save passwords in plain text
            if [[ "$key" != "auth_password" ]]; then
                echo "${key}=${CONFIG[$key]}"
            fi
        done
    } > "$config_file"

    print_success "Configuration saved"
}

# =============================================================================
# QUICK SETUP MODE
# =============================================================================

quick_setup() {
    print_section "Quick Setup Mode"

    echo "This will set up a basic ttyd instance with sensible defaults."
    echo

    # Instance name
    configure_instance_name

    # Command
    local default_shell="${SHELL:-/bin/bash}"
    CONFIG["command"]="$default_shell"

    # Defaults
    CONFIG["port"]="$TTYD_DEFAULT_PORT"
    CONFIG["writable"]="true"
    CONFIG["ipv6"]="false"
    CONFIG["ssl"]="false"
    CONFIG["auth_type"]="none"
    CONFIG["terminal_type"]="$TTYD_DEFAULT_TERMINAL"
    CONFIG["signal"]="$TTYD_DEFAULT_SIGNAL"
    CONFIG["debug_level"]="$TTYD_DEFAULT_DEBUG"
    CONFIG["ping_interval"]="$TTYD_DEFAULT_PING_INTERVAL"
    CONFIG["buffer_size"]="$TTYD_DEFAULT_BUFFER_SIZE"
    CONFIG["browser"]="false"
    CONFIG["once"]="false"
    CONFIG["exit_no_conn"]="false"
    CONFIG["check_origin"]="false"
    CONFIG["max_clients"]="0"
    CONFIG["url_args"]="false"

    print_success "Using shell: $default_shell"
    print_success "Port: ${CONFIG["port"]}"
    print_success "Writable: ${CONFIG["writable"]}"

    # Ask about authentication
    if confirm "Set up basic authentication?" "y"; then
        CONFIG["auth_type"]="basic"
        prompt_input "Username" "admin" "auth_username"
        prompt_password "Password" "auth_password"
    fi
}

# =============================================================================
# MAIN MENU
# =============================================================================

show_main_menu() {
    echo
    echo "Setup Mode:"
    echo "  1) Quick setup (recommended defaults)"
    echo "  2) Full configuration (all options)"
    echo "  3) Exit"
    echo

    read -r -p "Choose setup mode (1-3): " setup_mode

    case "$setup_mode" in
        1)
            quick_setup
            ;;
        2)
            full_configuration
            ;;
        3)
            echo "Exiting..."
            exit 0
            ;;
        *)
            print_error "Invalid choice"
            show_main_menu
            ;;
    esac
}

full_configuration() {
    # Instance name (required first)
    configure_instance_name

    # Command configuration
    configure_command

    # Network configuration
    configure_network

    # Authentication
    configure_authentication

    # SSL/TLS
    configure_ssl

    # Process options
    configure_process

    # Terminal options
    configure_terminal

    # Access control
    configure_access

    # Client management
    configure_clients

    # Client options
    if confirm "Configure client-side options (fonts, renderer, etc.)?" "n"; then
        configure_client_options
    fi

    # Performance
    if confirm "Configure performance options?" "n"; then
        configure_performance
    else
        CONFIG["debug_level"]="$TTYD_DEFAULT_DEBUG"
        CONFIG["buffer_size"]="$TTYD_DEFAULT_BUFFER_SIZE"
    fi

    # Browser
    configure_browser
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    print_header "ttyd Installation and Configuration Script v${SCRIPT_VERSION}"

    echo "This script will help you install and configure ttyd as a service."
    echo "ttyd shares your terminal over the web using a WebSocket connection."
    echo

    # Detect system
    detect_os
    detect_architecture

    # Check for unsupported OS
    if [[ "${CONFIG["os"]}" == "unknown" ]]; then
        print_error "Unsupported operating system"
        exit 1
    fi

    # Check dependencies
    check_dependencies

    # Install ttyd if needed
    if [[ "${CONFIG["ttyd_installed"]}" != "true" ]]; then
        if confirm "ttyd is not installed. Would you like to install it?" "y"; then
            case "${CONFIG["os"]}" in
                linux)
                    install_ttyd_linux
                    ;;
                macos)
                    install_ttyd_macos
                    ;;
            esac
        else
            print_error "ttyd is required. Please install it manually."
            exit 1
        fi
    fi

    # Show main menu
    show_main_menu

    # Build the command
    build_ttyd_command

    # Show summary
    show_configuration_summary

    # Confirm before proceeding
    if ! confirm "Proceed with service creation?" "y"; then
        echo "Aborted."
        exit 0
    fi

    # Save configuration
    save_configuration

    # Create service
    create_service

    # Final message
    print_header "Installation Complete!"

    local port="${CONFIG["port"]}"
    local protocol="http"
    [[ "${CONFIG["ssl"]}" == "true" ]] && protocol="https"

    echo "Your ttyd instance '${CONFIG["instance_name"]}' is now configured."
    echo
    echo "Access URL: ${protocol}://localhost:${port}/"
    echo

    if [[ "${CONFIG["auth_type"]}" == "basic" ]]; then
        echo "Login with:"
        echo "  Username: ${CONFIG["auth_username"]}"
        echo "  Password: (as configured)"
        echo
    fi

    echo "Thank you for using ttyd!"
}

# Run main
main "$@"
