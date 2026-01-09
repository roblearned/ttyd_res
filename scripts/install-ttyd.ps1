<#
.SYNOPSIS
    ttyd Installation and Configuration Script for Windows 11

.DESCRIPTION
    This script will:
    1. Install ttyd if not present (via WinGet, Scoop, or manual download)
    2. Guide you through all configuration options
    3. Create a named service instance (via NSSM or Windows Task Scheduler)

.NOTES
    Author: Generated for ttyd v1.7.7+
    Requires: Windows 10 1809+ (for ConPTY support) or Windows 11
    License: MIT

.EXAMPLE
    .\install-ttyd.ps1
#>

#Requires -Version 5.1

# =============================================================================
# CONSTANTS AND DEFAULTS
# =============================================================================

$script:SCRIPT_VERSION = "1.0.0"
$script:TTYD_DEFAULT_PORT = 7681
$script:TTYD_DEFAULT_TERMINAL = "xterm-256color"
$script:TTYD_DEFAULT_SIGNAL = "SIGHUP"
$script:TTYD_DEFAULT_DEBUG = 7
$script:TTYD_DEFAULT_PING_INTERVAL = 5
$script:TTYD_DEFAULT_BUFFER_SIZE = 4096

# Configuration storage
$script:Config = @{}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

function Write-Header {
    param([string]$Message)

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Blue
    Write-Host "  $Message" -ForegroundColor Blue
    Write-Host ("=" * 70) -ForegroundColor Blue
    Write-Host ""
}

function Write-Section {
    param([string]$Message)

    Write-Host ""
    Write-Host "-- $Message --" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Success {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[X] $Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host "[i] $Message" -ForegroundColor Blue
}

function Confirm-Prompt {
    param(
        [string]$Prompt,
        [bool]$Default = $false
    )

    $suffix = if ($Default) { "[Y/n]" } else { "[y/N]" }
    $response = Read-Host "$Prompt $suffix"

    if ([string]::IsNullOrWhiteSpace($response)) {
        return $Default
    }

    return $response -match "^[Yy]"
}

function Read-Input {
    param(
        [string]$Prompt,
        [string]$Default = "",
        [string]$ConfigKey
    )

    $displayPrompt = if ($Default) { "$Prompt [$Default]" } else { $Prompt }
    $response = Read-Host $displayPrompt

    if ([string]::IsNullOrWhiteSpace($response)) {
        $response = $Default
    }

    if ($ConfigKey) {
        $script:Config[$ConfigKey] = $response
    }

    return $response
}

function Read-SecureInput {
    param(
        [string]$Prompt,
        [string]$ConfigKey
    )

    $secure = Read-Host $Prompt -AsSecureString
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    )

    if ($ConfigKey) {
        $script:Config[$ConfigKey] = $plain
    }

    return $plain
}

function Read-Number {
    param(
        [string]$Prompt,
        [int]$Default,
        [string]$ConfigKey,
        [int]$Min = 0,
        [int]$Max = 65535
    )

    while ($true) {
        $response = Read-Host "$Prompt [$Default]"

        if ([string]::IsNullOrWhiteSpace($response)) {
            $script:Config[$ConfigKey] = $Default
            return $Default
        }

        $number = 0
        if ([int]::TryParse($response, [ref]$number)) {
            if ($number -ge $Min -and $number -le $Max) {
                $script:Config[$ConfigKey] = $number
                return $number
            }
        }

        Write-Error "Please enter a number between $Min and $Max"
    }
}

function Read-Choice {
    param(
        [string]$Prompt,
        [string[]]$Choices,
        [string]$ConfigKey,
        [int]$Default = 1
    )

    Write-Host $Prompt
    for ($i = 0; $i -lt $Choices.Count; $i++) {
        Write-Host "  $($i + 1)) $($Choices[$i])"
    }

    while ($true) {
        $response = Read-Host "Enter choice (1-$($Choices.Count)) [$Default]"

        if ([string]::IsNullOrWhiteSpace($response)) {
            $response = $Default
        }

        $number = 0
        if ([int]::TryParse($response, [ref]$number)) {
            if ($number -ge 1 -and $number -le $Choices.Count) {
                if ($ConfigKey) {
                    $script:Config[$ConfigKey] = $Choices[$number - 1]
                }
                return $number
            }
        }

        Write-Error "Please enter a number between 1 and $($Choices.Count)"
    }
}

# =============================================================================
# SYSTEM DETECTION
# =============================================================================

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-WindowsVersion {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $build = [int]$os.BuildNumber

    $script:Config["WindowsBuild"] = $build

    # Windows 10 1809 (build 17763) introduced ConPTY
    if ($build -ge 17763) {
        Write-Success "Windows build $build supports ConPTY"
        return $true
    } else {
        Write-Error "Windows build $build does not support ConPTY"
        Write-Info "ttyd requires Windows 10 1809 (build 17763) or later"
        return $false
    }
}

function Get-Architecture {
    $arch = [System.Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")

    switch ($arch) {
        "AMD64" { $script:Config["Arch"] = "win32"; return "win32" }
        "x86"   { $script:Config["Arch"] = "win32"; return "win32" }
        "ARM64" { $script:Config["Arch"] = "win32"; return "win32" }
        default { $script:Config["Arch"] = "win32"; return "win32" }
    }
}

function Test-TtydInstalled {
    $ttyd = Get-Command "ttyd" -ErrorAction SilentlyContinue

    if ($ttyd) {
        $version = & ttyd --version 2>&1 | Select-Object -First 1
        Write-Success "ttyd is installed: $version"
        $script:Config["TtydInstalled"] = $true
        $script:Config["TtydPath"] = $ttyd.Source
        return $true
    } else {
        Write-Warning "ttyd is not installed"
        $script:Config["TtydInstalled"] = $false
        return $false
    }
}

function Test-NssmInstalled {
    $nssm = Get-Command "nssm" -ErrorAction SilentlyContinue

    if ($nssm) {
        Write-Success "NSSM is installed"
        $script:Config["NssmInstalled"] = $true
        $script:Config["NssmPath"] = $nssm.Source
        return $true
    } else {
        $script:Config["NssmInstalled"] = $false
        return $false
    }
}

# =============================================================================
# INSTALLATION FUNCTIONS
# =============================================================================

function Install-TtydWinget {
    Write-Info "Installing ttyd via WinGet..."

    try {
        $result = winget install tsl0922.ttyd --accept-source-agreements --accept-package-agreements

        # Refresh PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("Path", "User")

        if (Get-Command "ttyd" -ErrorAction SilentlyContinue) {
            Write-Success "ttyd installed via WinGet"
            $script:Config["TtydInstalled"] = $true
            $script:Config["TtydPath"] = (Get-Command "ttyd").Source
            return $true
        }
    } catch {
        Write-Error "WinGet installation failed: $_"
    }

    return $false
}

function Install-TtydScoop {
    Write-Info "Installing ttyd via Scoop..."

    try {
        scoop install ttyd

        if (Get-Command "ttyd" -ErrorAction SilentlyContinue) {
            Write-Success "ttyd installed via Scoop"
            $script:Config["TtydInstalled"] = $true
            $script:Config["TtydPath"] = (Get-Command "ttyd").Source
            return $true
        }
    } catch {
        Write-Error "Scoop installation failed: $_"
    }

    return $false
}

function Install-TtydManual {
    Write-Info "Downloading ttyd binary..."

    $downloadUrl = "https://github.com/tsl0922/ttyd/releases/latest/download/ttyd.win32.exe"
    $installDir = "$env:ProgramFiles\ttyd"
    $installPath = "$installDir\ttyd.exe"

    $customPath = Read-Input -Prompt "Install directory" -Default $installDir

    if ($customPath -ne $installDir) {
        $installDir = $customPath
        $installPath = "$installDir\ttyd.exe"
    }

    try {
        # Create directory if needed
        if (-not (Test-Path $installDir)) {
            New-Item -ItemType Directory -Path $installDir -Force | Out-Null
        }

        # Download
        Write-Info "Downloading from: $downloadUrl"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $downloadUrl -OutFile $installPath -UseBasicParsing

        Write-Success "Downloaded to: $installPath"

        # Add to PATH
        $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
        if ($currentPath -notlike "*$installDir*") {
            if (Confirm-Prompt "Add ttyd to system PATH?" $true) {
                [Environment]::SetEnvironmentVariable("Path", "$currentPath;$installDir", "Machine")
                $env:Path = "$env:Path;$installDir"
                Write-Success "Added to PATH"
            }
        }

        $script:Config["TtydInstalled"] = $true
        $script:Config["TtydPath"] = $installPath
        return $true

    } catch {
        Write-Error "Manual installation failed: $_"
        return $false
    }
}

function Install-Ttyd {
    Write-Section "Installing ttyd"

    Write-Host "Choose installation method:"
    Write-Host "  1) WinGet (recommended)"
    Write-Host "  2) Scoop"
    Write-Host "  3) Manual download"
    Write-Host "  4) Skip (ttyd already installed elsewhere)"
    Write-Host ""

    $choice = Read-Host "Enter choice (1-4)"

    switch ($choice) {
        "1" {
            if (-not (Get-Command "winget" -ErrorAction SilentlyContinue)) {
                Write-Error "WinGet is not installed"
                return $false
            }
            return Install-TtydWinget
        }
        "2" {
            if (-not (Get-Command "scoop" -ErrorAction SilentlyContinue)) {
                Write-Error "Scoop is not installed"
                Write-Info "Install Scoop from: https://scoop.sh"
                return $false
            }
            return Install-TtydScoop
        }
        "3" {
            return Install-TtydManual
        }
        "4" {
            $customPath = Read-Input -Prompt "Enter path to ttyd.exe"
            if (Test-Path $customPath) {
                $script:Config["TtydPath"] = $customPath
                $script:Config["TtydInstalled"] = $true
                return $true
            } else {
                Write-Error "File not found: $customPath"
                return $false
            }
        }
        default {
            Write-Error "Invalid choice"
            return $false
        }
    }
}

function Install-Nssm {
    Write-Section "Installing NSSM (Non-Sucking Service Manager)"

    Write-Host "NSSM is required to run ttyd as a Windows service."
    Write-Host "Choose installation method:"
    Write-Host "  1) Download NSSM automatically"
    Write-Host "  2) Use Windows Task Scheduler instead (no NSSM)"
    Write-Host ""

    $choice = Read-Host "Enter choice (1-2) [2]"

    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "2" }

    switch ($choice) {
        "1" {
            $nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
            $tempZip = "$env:TEMP\nssm.zip"
            $tempDir = "$env:TEMP\nssm"
            $installDir = "$env:ProgramFiles\nssm"

            try {
                Write-Info "Downloading NSSM..."
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Invoke-WebRequest -Uri $nssmUrl -OutFile $tempZip -UseBasicParsing

                Write-Info "Extracting..."
                Expand-Archive -Path $tempZip -DestinationPath $tempDir -Force

                # Find the correct architecture binary
                $arch = if ([Environment]::Is64BitOperatingSystem) { "win64" } else { "win32" }
                $nssmExe = Get-ChildItem -Path $tempDir -Recurse -Filter "nssm.exe" |
                           Where-Object { $_.DirectoryName -like "*$arch*" } |
                           Select-Object -First 1

                if (-not $nssmExe) {
                    $nssmExe = Get-ChildItem -Path $tempDir -Recurse -Filter "nssm.exe" |
                               Select-Object -First 1
                }

                # Install
                if (-not (Test-Path $installDir)) {
                    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
                }

                Copy-Item -Path $nssmExe.FullName -Destination "$installDir\nssm.exe" -Force

                # Add to PATH
                $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
                if ($currentPath -notlike "*$installDir*") {
                    [Environment]::SetEnvironmentVariable("Path", "$currentPath;$installDir", "Machine")
                    $env:Path = "$env:Path;$installDir"
                }

                # Cleanup
                Remove-Item $tempZip -Force -ErrorAction SilentlyContinue
                Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue

                Write-Success "NSSM installed"
                $script:Config["NssmInstalled"] = $true
                $script:Config["NssmPath"] = "$installDir\nssm.exe"
                $script:Config["ServiceType"] = "nssm"
                return $true

            } catch {
                Write-Error "NSSM installation failed: $_"
                $script:Config["ServiceType"] = "task"
                return $false
            }
        }
        "2" {
            $script:Config["ServiceType"] = "task"
            Write-Info "Will use Windows Task Scheduler"
            return $true
        }
        default {
            $script:Config["ServiceType"] = "task"
            return $true
        }
    }
}

# =============================================================================
# CONFIGURATION FUNCTIONS
# =============================================================================

function Configure-InstanceName {
    Write-Section "Instance Configuration"

    Write-Host "Enter a unique name for this ttyd instance."
    Write-Host "This will be used for the service name and configuration."
    Write-Host "Example: web-shell, admin-terminal, dev-console"
    Write-Host ""

    while ($true) {
        $name = Read-Input -Prompt "Instance name" -Default "ttyd-default"

        # Validate: alphanumeric, hyphens, underscores only
        if ($name -match "^[a-zA-Z][a-zA-Z0-9_-]*$") {
            $script:Config["InstanceName"] = $name
            Write-Success "Instance name: $name"
            break
        } else {
            Write-Error "Invalid name. Use only letters, numbers, hyphens, and underscores. Must start with a letter."
        }
    }
}

function Configure-Command {
    Write-Section "Command Configuration"

    Write-Host "Specify the command/shell to run in the terminal."
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  - cmd.exe (Windows Command Prompt)"
    Write-Host "  - powershell.exe (Windows PowerShell)"
    Write-Host "  - pwsh.exe (PowerShell Core)"
    Write-Host "  - wsl.exe (Windows Subsystem for Linux)"
    Write-Host "  - C:\Program Files\Git\bin\bash.exe (Git Bash)"
    Write-Host ""

    # Detect available shells
    $defaultShell = "powershell.exe"

    if (Get-Command "pwsh" -ErrorAction SilentlyContinue) {
        $defaultShell = "pwsh.exe"
    }

    $command = Read-Input -Prompt "Command to run" -Default $defaultShell -ConfigKey "Command"

    if (Confirm-Prompt "Pass arguments to the command?" $false) {
        Read-Input -Prompt "Command arguments (space-separated)" -ConfigKey "CommandArgs"
    }
}

function Configure-Network {
    Write-Section "Network Configuration"

    # Port
    Write-Host "Port to listen on (0 for random port, default: $script:TTYD_DEFAULT_PORT)"
    Read-Number -Prompt "Port" -Default $script:TTYD_DEFAULT_PORT -ConfigKey "Port" -Min 0 -Max 65535

    # Interface binding
    Write-Host ""
    if (Confirm-Prompt "Bind to a specific network interface?" $false) {
        Write-Host "Enter interface name or IP address"
        Write-Host "Examples: 127.0.0.1 (localhost only), 0.0.0.0 (all interfaces)"
        Read-Input -Prompt "Interface" -ConfigKey "Interface"
    }

    # IPv6
    Write-Host ""
    $script:Config["IPv6"] = Confirm-Prompt "Enable IPv6 support?" $false
}

function Configure-Authentication {
    Write-Section "Authentication Configuration"

    Write-Host "Authentication protects your terminal from unauthorized access."
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  1) No authentication (not recommended for public access)"
    Write-Host "  2) Basic authentication (username:password)"
    Write-Host "  3) Proxy authentication header (for reverse proxy setups)"
    Write-Host ""

    $choice = Read-Host "Choose authentication method (1-3) [1]"

    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "1" }

    switch ($choice) {
        "1" {
            $script:Config["AuthType"] = "none"
            Write-Warning "No authentication configured. Terminal will be publicly accessible!"
        }
        "2" {
            $script:Config["AuthType"] = "basic"
            Read-Input -Prompt "Username" -ConfigKey "AuthUsername"
            Read-SecureInput -Prompt "Password" -ConfigKey "AuthPassword"

            if ([string]::IsNullOrWhiteSpace($script:Config["AuthUsername"]) -or
                [string]::IsNullOrWhiteSpace($script:Config["AuthPassword"])) {
                Write-Error "Username and password cannot be empty"
                exit 1
            }
            Write-Success "Basic authentication configured"
        }
        "3" {
            $script:Config["AuthType"] = "header"
            Write-Host "Enter the HTTP header name that contains the authenticated user"
            Read-Input -Prompt "Auth header name" -Default "X-Authenticated-User" -ConfigKey "AuthHeader"
            Write-Success "Proxy authentication configured via header: $($script:Config['AuthHeader'])"
        }
        default {
            $script:Config["AuthType"] = "none"
        }
    }
}

function Configure-SSL {
    Write-Section "SSL/TLS Configuration"

    Write-Host "SSL/TLS encrypts the connection between clients and the server."
    Write-Host ""

    if (Confirm-Prompt "Enable SSL/TLS?" $false) {
        $script:Config["SSL"] = $true

        Write-Host ""
        Write-Host "Enter paths to your SSL certificate files:"

        while ($true) {
            $certPath = Read-Input -Prompt "SSL certificate file path" -ConfigKey "SSLCert"
            if (Test-Path $certPath) {
                Write-Success "Certificate file found"
                break
            } else {
                Write-Error "File not found: $certPath"
            }
        }

        while ($true) {
            $keyPath = Read-Input -Prompt "SSL private key file path" -ConfigKey "SSLKey"
            if (Test-Path $keyPath) {
                Write-Success "Key file found"
                break
            } else {
                Write-Error "File not found: $keyPath"
            }
        }

        if (Confirm-Prompt "Enable client certificate verification?" $false) {
            while ($true) {
                $caPath = Read-Input -Prompt "CA certificate file path" -ConfigKey "SSLCA"
                if (Test-Path $caPath) {
                    Write-Success "CA certificate file found"
                    break
                } else {
                    Write-Error "File not found: $caPath"
                }
            }
        }
    } else {
        $script:Config["SSL"] = $false
    }
}

function Configure-Process {
    Write-Section "Process Configuration"

    # Working directory
    if (Confirm-Prompt "Set a specific working directory?" $false) {
        while ($true) {
            $cwd = Read-Input -Prompt "Working directory" -Default $env:USERPROFILE -ConfigKey "Cwd"
            if (Test-Path $cwd -PathType Container) {
                Write-Success "Working directory: $cwd"
                break
            } else {
                Write-Error "Directory not found: $cwd"
            }
        }
    }

    # Signal (less relevant on Windows, but still supported)
    Write-Host ""
    Write-Host "Signal to send to the process when closing (Windows uses process termination)"
    Read-Input -Prompt "Signal" -Default $script:TTYD_DEFAULT_SIGNAL -ConfigKey "Signal"
}

function Configure-Terminal {
    Write-Section "Terminal Configuration"

    # Terminal type
    Write-Host "Terminal type reported to the shell"
    Write-Host "Common types: xterm-256color, xterm, vt100"
    Read-Input -Prompt "Terminal type" -Default $script:TTYD_DEFAULT_TERMINAL -ConfigKey "TerminalType"

    # Custom index
    Write-Host ""
    if (Confirm-Prompt "Use a custom index.html file?" $false) {
        while ($true) {
            $indexPath = Read-Input -Prompt "Path to custom index.html" -ConfigKey "CustomIndex"
            if (Test-Path $indexPath) {
                Write-Success "Custom index file found"
                break
            } else {
                Write-Error "File not found: $indexPath"
            }
        }
    }

    # Base path
    Write-Host ""
    if (Confirm-Prompt "Set a base path (for reverse proxy)?" $false) {
        Read-Input -Prompt "Base path" -Default "/" -ConfigKey "BasePath"
    }
}

function Configure-Access {
    Write-Section "Access Control Configuration"

    # Writable
    Write-Host "By default, ttyd runs in read-only mode (clients cannot type)."
    $script:Config["Writable"] = Confirm-Prompt "Allow clients to write to the terminal?" $true

    if ($script:Config["Writable"]) {
        Write-Info "Terminal will be writable"
    } else {
        Write-Info "Terminal will be read-only"
    }

    # URL arguments
    Write-Host ""
    if (Confirm-Prompt "Allow command-line arguments from URL? (e.g., ?arg=foo)" $false) {
        $script:Config["UrlArgs"] = $true
        Write-Warning "URL arguments enabled - be careful with this option!"
    } else {
        $script:Config["UrlArgs"] = $false
    }
}

function Configure-Clients {
    Write-Section "Client Management Configuration"

    # Max clients
    Write-Host "Maximum number of concurrent clients (0 = unlimited)"
    Read-Number -Prompt "Max clients" -Default 0 -ConfigKey "MaxClients" -Min 0 -Max 10000

    # Once mode
    Write-Host ""
    $script:Config["Once"] = Confirm-Prompt "Accept only one client and exit on disconnect? (once mode)" $false

    # Exit on no connections
    if (-not $script:Config["Once"]) {
        Write-Host ""
        $script:Config["ExitNoConn"] = Confirm-Prompt "Exit when all clients disconnect?" $false
    }

    # Check origin
    Write-Host ""
    $script:Config["CheckOrigin"] = Confirm-Prompt "Check WebSocket origin (reject cross-origin connections)?" $false

    # Ping interval
    Write-Host ""
    Write-Host "WebSocket ping interval in seconds (for connection keepalive)"
    Read-Number -Prompt "Ping interval" -Default $script:TTYD_DEFAULT_PING_INTERVAL -ConfigKey "PingInterval" -Min 0 -Max 3600
}

function Configure-ClientOptions {
    Write-Section "Client-Side Options (xterm.js)"

    Write-Host "These options customize the terminal appearance and behavior for clients."
    Write-Host ""

    $clientOpts = @()

    # Font size
    if (Confirm-Prompt "Set custom font size?" $false) {
        $fontSize = Read-Number -Prompt "Font size (pixels)" -Default 14 -ConfigKey "ClientFontSize" -Min 8 -Max 72
        $clientOpts += "fontSize=$fontSize"
    }

    # Renderer
    Write-Host ""
    Write-Host "Renderer type:"
    Write-Host "  1) WebGL (default, faster)"
    Write-Host "  2) Canvas (more compatible)"
    $renderer = Read-Host "Choose renderer (1-2) [1]"
    if ($renderer -eq "2") {
        $clientOpts += "rendererType=canvas"
    }

    # Cursor style
    Write-Host ""
    Write-Host "Cursor style:"
    Write-Host "  1) Block (default)"
    Write-Host "  2) Underline"
    Write-Host "  3) Bar"
    $cursor = Read-Host "Choose cursor style (1-3) [1]"
    switch ($cursor) {
        "2" { $clientOpts += "cursorStyle=underline" }
        "3" { $clientOpts += "cursorStyle=bar" }
    }

    # Special features
    Write-Host ""
    if (Confirm-Prompt "Enable ZMODEM file transfer?" $false) {
        $clientOpts += "enableZmodem=true"
    }

    if (Confirm-Prompt "Enable trzsz file transfer?" $false) {
        $clientOpts += "enableTrzsz=true"
    }

    if (Confirm-Prompt "Enable Sixel image support?" $false) {
        $clientOpts += "enableSixel=true"
    }

    # Alerts
    if (Confirm-Prompt "Disable page leave alert?" $false) {
        $clientOpts += "disableLeaveAlert=true"
    }

    if (Confirm-Prompt "Disable resize overlay?" $false) {
        $clientOpts += "disableResizeOverlay=true"
    }

    if (Confirm-Prompt "Disable auto-reconnect?" $false) {
        $clientOpts += "disableReconnect=true"
    }

    # Fixed title
    if (Confirm-Prompt "Set fixed browser window title?" $false) {
        $title = Read-Input -Prompt "Window title"
        if (-not [string]::IsNullOrWhiteSpace($title)) {
            $clientOpts += "titleFixed=$title"
        }
    }

    $script:Config["ClientOptions"] = $clientOpts
}

function Configure-Performance {
    Write-Section "Performance Configuration"

    # Debug level
    Write-Host "Debug/log level (bitmask: 1=ERR, 2=WARN, 4=NOTICE)"
    Write-Host "  7 = All messages (ERR + WARN + NOTICE)"
    Write-Host "  3 = Errors and warnings only"
    Write-Host "  1 = Errors only"
    Read-Number -Prompt "Debug level" -Default $script:TTYD_DEFAULT_DEBUG -ConfigKey "DebugLevel" -Min 0 -Max 255

    # Buffer size
    Write-Host ""
    Write-Host "Server buffer size (larger values can improve file transfer throughput)"
    Read-Number -Prompt "Buffer size (bytes)" -Default $script:TTYD_DEFAULT_BUFFER_SIZE -ConfigKey "BufferSize" -Min 1024 -Max 1048576
}

function Configure-Browser {
    Write-Section "Browser Options"

    $script:Config["Browser"] = Confirm-Prompt "Open terminal in browser automatically on start?" $false
}

# =============================================================================
# COMMAND BUILDING
# =============================================================================

function Build-TtydCommand {
    $ttydPath = $script:Config["TtydPath"]
    $args = @()

    # Network options
    if ($script:Config["Port"]) { $args += "-p"; $args += $script:Config["Port"] }
    if ($script:Config["Interface"]) { $args += "-i"; $args += $script:Config["Interface"] }
    if ($script:Config["IPv6"]) { $args += "-6" }

    # Authentication
    if ($script:Config["AuthType"] -eq "basic") {
        $args += "-c"
        $args += "$($script:Config['AuthUsername']):$($script:Config['AuthPassword'])"
    } elseif ($script:Config["AuthType"] -eq "header") {
        $args += "-H"
        $args += $script:Config["AuthHeader"]
    }

    # SSL
    if ($script:Config["SSL"]) {
        $args += "-S"
        $args += "-C"; $args += $script:Config["SSLCert"]
        $args += "-K"; $args += $script:Config["SSLKey"]
        if ($script:Config["SSLCA"]) {
            $args += "-A"; $args += $script:Config["SSLCA"]
        }
    }

    # Process options
    if ($script:Config["Cwd"]) { $args += "-w"; $args += $script:Config["Cwd"] }
    if ($script:Config["Signal"]) { $args += "-s"; $args += $script:Config["Signal"] }

    # Terminal options
    if ($script:Config["TerminalType"]) { $args += "-T"; $args += $script:Config["TerminalType"] }
    if ($script:Config["CustomIndex"]) { $args += "-I"; $args += $script:Config["CustomIndex"] }
    if ($script:Config["BasePath"]) { $args += "-b"; $args += $script:Config["BasePath"] }

    # Access control
    if ($script:Config["Writable"]) { $args += "-W" }
    if ($script:Config["UrlArgs"]) { $args += "-a" }

    # Client management
    if ($script:Config["MaxClients"] -and $script:Config["MaxClients"] -ne 0) {
        $args += "-m"; $args += $script:Config["MaxClients"]
    }
    if ($script:Config["Once"]) { $args += "-o" }
    if ($script:Config["ExitNoConn"]) { $args += "-q" }
    if ($script:Config["CheckOrigin"]) { $args += "-O" }
    if ($script:Config["PingInterval"]) { $args += "-P"; $args += $script:Config["PingInterval"] }

    # Client options
    if ($script:Config["ClientOptions"]) {
        foreach ($opt in $script:Config["ClientOptions"]) {
            $args += "-t"; $args += $opt
        }
    }

    # Performance
    if ($script:Config["DebugLevel"]) { $args += "-d"; $args += $script:Config["DebugLevel"] }
    if ($script:Config["BufferSize"]) { $args += "-f"; $args += $script:Config["BufferSize"] }

    # Browser
    if ($script:Config["Browser"]) { $args += "-B" }

    # Command
    $args += $script:Config["Command"]
    if ($script:Config["CommandArgs"]) {
        $args += $script:Config["CommandArgs"] -split " "
    }

    $script:Config["TtydArgs"] = $args
    $script:Config["TtydFullCommand"] = "$ttydPath $($args -join ' ')"
}

# =============================================================================
# SERVICE CREATION
# =============================================================================

function Create-NssmService {
    $instanceName = $script:Config["InstanceName"]
    $serviceName = "ttyd-$instanceName"
    $ttydPath = $script:Config["TtydPath"]
    $nssmPath = $script:Config["NssmPath"]

    Write-Section "Creating NSSM Service"

    # Build arguments string
    $argsString = $script:Config["TtydArgs"] -join " "

    Write-Info "Creating service: $serviceName"

    try {
        # Install the service
        & $nssmPath install $serviceName $ttydPath $argsString

        # Configure the service
        & $nssmPath set $serviceName DisplayName "ttyd Terminal: $instanceName"
        & $nssmPath set $serviceName Description "Web-based terminal sharing service - $instanceName"
        & $nssmPath set $serviceName Start SERVICE_AUTO_START
        & $nssmPath set $serviceName AppStdout "$env:TEMP\ttyd-$instanceName.log"
        & $nssmPath set $serviceName AppStderr "$env:TEMP\ttyd-$instanceName.err"
        & $nssmPath set $serviceName AppRotateFiles 1
        & $nssmPath set $serviceName AppRotateBytes 1048576

        Write-Success "Service created"

        if (Confirm-Prompt "Start the service now?" $true) {
            & $nssmPath start $serviceName
            Start-Sleep -Seconds 2

            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service -and $service.Status -eq "Running") {
                Write-Success "Service started successfully"
            } else {
                Write-Warning "Service may not have started correctly. Check logs."
            }
        }

        # Print management commands
        Write-Host ""
        Write-Section "Service Management Commands"
        Write-Host "  Start:   nssm start $serviceName"
        Write-Host "  Stop:    nssm stop $serviceName"
        Write-Host "  Restart: nssm restart $serviceName"
        Write-Host "  Status:  nssm status $serviceName"
        Write-Host "  Edit:    nssm edit $serviceName"
        Write-Host "  Remove:  nssm remove $serviceName"
        Write-Host "  Logs:    Get-Content $env:TEMP\ttyd-$instanceName.log"

    } catch {
        Write-Error "Failed to create service: $_"
        return $false
    }

    return $true
}

function Create-ScheduledTask {
    $instanceName = $script:Config["InstanceName"]
    $taskName = "ttyd-$instanceName"
    $ttydPath = $script:Config["TtydPath"]

    Write-Section "Creating Windows Task Scheduler Task"

    # Build arguments string
    $argsString = $script:Config["TtydArgs"] -join " "

    Write-Info "Creating scheduled task: $taskName"

    try {
        # Create the action
        $action = New-ScheduledTaskAction -Execute $ttydPath -Argument $argsString

        # Create trigger (at startup)
        $trigger = New-ScheduledTaskTrigger -AtStartup

        # Create settings
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
            -ExecutionTimeLimit (New-TimeSpan -Days 365)

        # Create principal (run as current user)
        $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType S4U -RunLevel Highest

        # Register the task
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
            -Settings $settings -Principal $principal -Description "ttyd Terminal: $instanceName" -Force

        Write-Success "Scheduled task created"

        if (Confirm-Prompt "Start the task now?" $true) {
            Start-ScheduledTask -TaskName $taskName
            Start-Sleep -Seconds 2

            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($task -and $task.State -eq "Running") {
                Write-Success "Task started successfully"
            } else {
                Write-Warning "Task may not be running. Check Task Scheduler."
            }
        }

        # Print management commands
        Write-Host ""
        Write-Section "Task Management Commands (PowerShell)"
        Write-Host "  Start:   Start-ScheduledTask -TaskName '$taskName'"
        Write-Host "  Stop:    Stop-ScheduledTask -TaskName '$taskName'"
        Write-Host "  Status:  Get-ScheduledTask -TaskName '$taskName' | Select-Object State"
        Write-Host "  Remove:  Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false"
        Write-Host ""
        Write-Host "Or use Task Scheduler GUI: taskschd.msc"

    } catch {
        Write-Error "Failed to create scheduled task: $_"
        return $false
    }

    return $true
}

function Create-Service {
    if ($script:Config["ServiceType"] -eq "nssm" -and $script:Config["NssmInstalled"]) {
        return Create-NssmService
    } else {
        return Create-ScheduledTask
    }
}

# =============================================================================
# CONFIGURATION SUMMARY
# =============================================================================

function Show-ConfigurationSummary {
    Write-Section "Configuration Summary"

    Write-Host "Instance Name: $($script:Config['InstanceName'])"
    Write-Host "Command:       $($script:Config['Command']) $($script:Config['CommandArgs'])"
    Write-Host "Port:          $($script:Config['Port'])"
    Write-Host "Writable:      $($script:Config['Writable'])"
    Write-Host "SSL:           $($script:Config['SSL'])"
    Write-Host "Auth Type:     $($script:Config['AuthType'])"
    Write-Host ""
    Write-Host "Full Command:"
    Write-Host "  $($script:Config['TtydFullCommand'])"
    Write-Host ""
}

function Save-Configuration {
    $instanceName = $script:Config["InstanceName"]
    $configDir = "$env:APPDATA\ttyd"
    $configFile = "$configDir\$instanceName.json"

    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }

    Write-Info "Saving configuration to: $configFile"

    # Remove sensitive data
    $configToSave = $script:Config.Clone()
    $configToSave.Remove("AuthPassword")

    $configToSave | ConvertTo-Json -Depth 10 | Out-File -FilePath $configFile -Encoding UTF8

    Write-Success "Configuration saved"
}

# =============================================================================
# QUICK SETUP MODE
# =============================================================================

function Quick-Setup {
    Write-Section "Quick Setup Mode"

    Write-Host "This will set up a basic ttyd instance with sensible defaults."
    Write-Host ""

    # Instance name
    Configure-InstanceName

    # Command
    $script:Config["Command"] = "powershell.exe"
    if (Get-Command "pwsh" -ErrorAction SilentlyContinue) {
        $script:Config["Command"] = "pwsh.exe"
    }

    # Defaults
    $script:Config["Port"] = $script:TTYD_DEFAULT_PORT
    $script:Config["Writable"] = $true
    $script:Config["IPv6"] = $false
    $script:Config["SSL"] = $false
    $script:Config["AuthType"] = "none"
    $script:Config["TerminalType"] = $script:TTYD_DEFAULT_TERMINAL
    $script:Config["Signal"] = $script:TTYD_DEFAULT_SIGNAL
    $script:Config["DebugLevel"] = $script:TTYD_DEFAULT_DEBUG
    $script:Config["PingInterval"] = $script:TTYD_DEFAULT_PING_INTERVAL
    $script:Config["BufferSize"] = $script:TTYD_DEFAULT_BUFFER_SIZE
    $script:Config["Browser"] = $false
    $script:Config["Once"] = $false
    $script:Config["ExitNoConn"] = $false
    $script:Config["CheckOrigin"] = $false
    $script:Config["MaxClients"] = 0
    $script:Config["UrlArgs"] = $false

    Write-Success "Using shell: $($script:Config['Command'])"
    Write-Success "Port: $($script:Config['Port'])"
    Write-Success "Writable: $($script:Config['Writable'])"

    # Ask about authentication
    if (Confirm-Prompt "Set up basic authentication?" $true) {
        $script:Config["AuthType"] = "basic"
        Read-Input -Prompt "Username" -Default "admin" -ConfigKey "AuthUsername"
        Read-SecureInput -Prompt "Password" -ConfigKey "AuthPassword"
    }
}

function Full-Configuration {
    # Instance name (required first)
    Configure-InstanceName

    # Command configuration
    Configure-Command

    # Network configuration
    Configure-Network

    # Authentication
    Configure-Authentication

    # SSL/TLS
    Configure-SSL

    # Process options
    Configure-Process

    # Terminal options
    Configure-Terminal

    # Access control
    Configure-Access

    # Client management
    Configure-Clients

    # Client options
    if (Confirm-Prompt "Configure client-side options (fonts, renderer, etc.)?" $false) {
        Configure-ClientOptions
    }

    # Performance
    if (Confirm-Prompt "Configure performance options?" $false) {
        Configure-Performance
    } else {
        $script:Config["DebugLevel"] = $script:TTYD_DEFAULT_DEBUG
        $script:Config["BufferSize"] = $script:TTYD_DEFAULT_BUFFER_SIZE
    }

    # Browser
    Configure-Browser
}

# =============================================================================
# MAIN MENU
# =============================================================================

function Show-MainMenu {
    Write-Host ""
    Write-Host "Setup Mode:"
    Write-Host "  1) Quick setup (recommended defaults)"
    Write-Host "  2) Full configuration (all options)"
    Write-Host "  3) Exit"
    Write-Host ""

    $choice = Read-Host "Choose setup mode (1-3)"

    switch ($choice) {
        "1" { Quick-Setup }
        "2" { Full-Configuration }
        "3" { Write-Host "Exiting..."; exit 0 }
        default {
            Write-Error "Invalid choice"
            Show-MainMenu
        }
    }
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

function Main {
    Write-Header "ttyd Installation and Configuration Script v$script:SCRIPT_VERSION"

    Write-Host "This script will help you install and configure ttyd as a service."
    Write-Host "ttyd shares your terminal over the web using a WebSocket connection."
    Write-Host ""

    # Check if running as administrator
    if (-not (Test-Administrator)) {
        Write-Warning "Not running as Administrator. Some features may not work."
        Write-Info "For full functionality, run PowerShell as Administrator."
        Write-Host ""
    }

    # Check Windows version
    if (-not (Get-WindowsVersion)) {
        Write-Error "This Windows version is not supported."
        exit 1
    }

    # Get architecture
    Get-Architecture

    # Check if ttyd is installed
    if (-not (Test-TtydInstalled)) {
        if (Confirm-Prompt "ttyd is not installed. Would you like to install it?" $true) {
            if (-not (Install-Ttyd)) {
                Write-Error "Failed to install ttyd"
                exit 1
            }
        } else {
            Write-Error "ttyd is required. Please install it manually."
            exit 1
        }
    }

    # Check/install NSSM for service creation
    if (-not (Test-NssmInstalled)) {
        Install-Nssm
    } else {
        $script:Config["ServiceType"] = "nssm"
    }

    # Show main menu
    Show-MainMenu

    # Build the command
    Build-TtydCommand

    # Show summary
    Show-ConfigurationSummary

    # Confirm before proceeding
    if (-not (Confirm-Prompt "Proceed with service creation?" $true)) {
        Write-Host "Aborted."
        exit 0
    }

    # Save configuration
    Save-Configuration

    # Create service
    Create-Service

    # Final message
    Write-Header "Installation Complete!"

    $port = $script:Config["Port"]
    $protocol = if ($script:Config["SSL"]) { "https" } else { "http" }

    Write-Host "Your ttyd instance '$($script:Config['InstanceName'])' is now configured."
    Write-Host ""
    Write-Host "Access URL: ${protocol}://localhost:${port}/"
    Write-Host ""

    if ($script:Config["AuthType"] -eq "basic") {
        Write-Host "Login with:"
        Write-Host "  Username: $($script:Config['AuthUsername'])"
        Write-Host "  Password: (as configured)"
        Write-Host ""
    }

    Write-Host "Thank you for using ttyd!"
}

# Run main
Main
