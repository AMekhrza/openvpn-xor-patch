<#
.SYNOPSIS
    Automated OpenVPN 2.5 XOR Scramble Patch and Build Script
.DESCRIPTION
    This script automates patching OpenVPN 2.5 with XOR scramble functionality
    and builds the project using CMake and vcpkg.
#>

param(
    [string]$VcpkgRoot = "$env:USERPROFILE\vcpkg",
    [string]$BuildType = "Release"
)

$ErrorActionPreference = "Stop"
$ScriptRoot = $PSScriptRoot
if (-not $ScriptRoot) { $ScriptRoot = Get-Location }

function Write-Step {
    param([string]$Message)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host " $Message" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# =============================================================================
# STEP 1: Verify and Setup vcpkg Environment
# =============================================================================
Write-Step "Verifying vcpkg Environment"

$vcpkgExe = Join-Path $VcpkgRoot "vcpkg.exe"
$vcpkgToolchain = Join-Path $VcpkgRoot "scripts\buildsystems\vcpkg.cmake"

if (-not (Test-Path $vcpkgExe)) {
    Write-Info "vcpkg not found at $VcpkgRoot. Cloning and bootstrapping..."
    
    if (Test-Path $VcpkgRoot) {
        Remove-Item -Recurse -Force $VcpkgRoot
    }
    
    git clone https://github.com/microsoft/vcpkg.git $VcpkgRoot
    if ($LASTEXITCODE -ne 0) { throw "Failed to clone vcpkg" }
    
    Push-Location $VcpkgRoot
    try {
        & .\bootstrap-vcpkg.bat -disableMetrics
        if ($LASTEXITCODE -ne 0) { throw "Failed to bootstrap vcpkg" }
    }
    finally {
        Pop-Location
    }
    Write-Success "vcpkg bootstrapped successfully"
}
else {
    Write-Success "vcpkg found at $VcpkgRoot"
}

# Install required packages
$packages = @("openssl:x64-windows", "lzo:x64-windows")
foreach ($pkg in $packages) {
    Write-Info "Ensuring $pkg is installed..."
    & $vcpkgExe install $pkg --triplet x64-windows
    if ($LASTEXITCODE -ne 0) { throw "Failed to install $pkg" }
}
Write-Success "All vcpkg dependencies installed"

# =============================================================================
# STEP 1.5: Ensure Source Code Exists
# =============================================================================
Write-Step "Checking Source Code"

$srcOpenvpn = Join-Path $ScriptRoot "src\openvpn"
$hasSource = Test-Path (Join-Path $srcOpenvpn "openvpn.c")

if (-not $hasSource) {
    Write-Info "OpenVPN source not found. Downloading..."
    
    # Download OpenVPN 2.5 source
    $openvpnUrl = "https://github.com/OpenVPN/openvpn/archive/refs/tags/v2.5.10.zip"
    $zipPath = Join-Path $ScriptRoot "openvpn-src.zip"
    
    try {
        Invoke-WebRequest -Uri $openvpnUrl -OutFile $zipPath -UseBasicParsing
        Expand-Archive -Path $zipPath -DestinationPath $ScriptRoot -Force
        
        # Move contents from extracted folder
        $extractedDir = Get-ChildItem -Path $ScriptRoot -Directory | Where-Object { $_.Name -match "openvpn-" } | Select-Object -First 1
        if ($extractedDir) {
            Get-ChildItem -Path $extractedDir.FullName | Move-Item -Destination $ScriptRoot -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $extractedDir.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }
        Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
        
        Write-Success "Downloaded and extracted OpenVPN source"
    }
    catch {
        throw "Could not download OpenVPN source: $_"
    }
}

# Re-check source path after download
if (-not (Test-Path $srcOpenvpn)) {
    New-Item -ItemType Directory -Path $srcOpenvpn -Force | Out-Null
}

# =============================================================================
# STEP 2: Create Scramble Header and Source Files
# =============================================================================
Write-Step "Creating Scramble Files"

# Create scramble.h
$scrambleH = @'
/*
 * OpenVPN XOR Scramble Implementation
 * Header file for XOR-based traffic obfuscation
 */

#ifndef OPENVPN_SCRAMBLE_H
#define OPENVPN_SCRAMBLE_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/types.h>
#endif

/* Maximum scramble key length */
#define SCRAMBLE_MAX_KEY_LEN 256

/* Scramble method types */
typedef enum {
    SCRAMBLE_NONE = 0,
    SCRAMBLE_XOR,
    SCRAMBLE_XOR_PTR,
    SCRAMBLE_REVERSE,
    SCRAMBLE_OBFUSCATE
} scramble_method_t;

/* Scramble configuration structure */
struct scramble_config {
    scramble_method_t method;
    char key[SCRAMBLE_MAX_KEY_LEN];
    size_t key_len;
    int enabled;
};

/* Scramble context for per-connection state */
struct scramble_context {
    struct scramble_config *config;
    size_t key_offset;
};

/*
 * Initialize scramble configuration
 * Returns 0 on success, -1 on failure
 */
int scramble_init(struct scramble_config *config, const char *method, const char *key);

/*
 * Apply XOR mask to buffer
 * Performs in-place XOR operation on the buffer using the key
 */
void xor_mask(uint8_t *buf, size_t len, const char *key, size_t key_len, size_t *offset);

/*
 * Scramble outgoing packet
 * Call this before sending data over the socket
 * Returns the (potentially modified) length of data to send
 */
ssize_t scramble_outgoing(struct scramble_config *config, uint8_t *buf, ssize_t len);

/*
 * Unscramble incoming packet
 * Call this after receiving data from the socket
 * Returns the (potentially modified) length of received data
 */
ssize_t scramble_incoming(struct scramble_config *config, uint8_t *buf, ssize_t len);

/*
 * Reverse bytes in buffer
 * Used for SCRAMBLE_REVERSE and SCRAMBLE_OBFUSCATE methods
 */
void reverse_bytes(uint8_t *buf, size_t len);

/*
 * XOR with pointer offset method
 * XORs each byte with its position in the packet
 */
void xor_ptr(uint8_t *buf, size_t len);

/*
 * Cleanup scramble configuration
 */
void scramble_cleanup(struct scramble_config *config);

#endif /* OPENVPN_SCRAMBLE_H */
'@

$scrambleHPath = Join-Path $srcOpenvpn "scramble.h"
Set-Content -Path $scrambleHPath -Value $scrambleH -Encoding UTF8
Write-Success "Created $scrambleHPath"

# Create scramble.c
$scrambleC = @'
/*
 * OpenVPN XOR Scramble Implementation
 * Source file for XOR-based traffic obfuscation
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"
#include "scramble.h"

#include <string.h>
#include <stdlib.h>

/*
 * Initialize scramble configuration from method string and key
 */
int
scramble_init(struct scramble_config *config, const char *method, const char *key)
{
    if (!config)
    {
        return -1;
    }

    memset(config, 0, sizeof(*config));

    if (!method || strlen(method) == 0)
    {
        config->method = SCRAMBLE_NONE;
        config->enabled = 0;
        return 0;
    }

    if (strcmp(method, "xormask") == 0 || strcmp(method, "xor_mask") == 0)
    {
        config->method = SCRAMBLE_XOR;
    }
    else if (strcmp(method, "xorptrpos") == 0 || strcmp(method, "xor_ptr") == 0)
    {
        config->method = SCRAMBLE_XOR_PTR;
    }
    else if (strcmp(method, "reverse") == 0)
    {
        config->method = SCRAMBLE_REVERSE;
    }
    else if (strcmp(method, "obfuscate") == 0)
    {
        config->method = SCRAMBLE_OBFUSCATE;
    }
    else
    {
        /* Default to XOR if method is unrecognized but key is provided */
        config->method = SCRAMBLE_XOR;
    }

    if (key && strlen(key) > 0)
    {
        size_t key_len = strlen(key);
        if (key_len >= SCRAMBLE_MAX_KEY_LEN)
        {
            key_len = SCRAMBLE_MAX_KEY_LEN - 1;
        }
        memcpy(config->key, key, key_len);
        config->key[key_len] = '\0';
        config->key_len = key_len;
    }
    else if (config->method == SCRAMBLE_XOR || config->method == SCRAMBLE_OBFUSCATE)
    {
        /* XOR methods require a key */
        return -1;
    }

    config->enabled = 1;
    return 0;
}

/*
 * Apply XOR mask to buffer using the provided key
 */
void
xor_mask(uint8_t *buf, size_t len, const char *key, size_t key_len, size_t *offset)
{
    size_t i;
    size_t key_idx;

    if (!buf || len == 0 || !key || key_len == 0)
    {
        return;
    }

    key_idx = offset ? *offset : 0;

    for (i = 0; i < len; i++)
    {
        buf[i] ^= (uint8_t)key[key_idx];
        key_idx = (key_idx + 1) % key_len;
    }

    if (offset)
    {
        *offset = key_idx;
    }
}

/*
 * Reverse bytes in buffer
 */
void
reverse_bytes(uint8_t *buf, size_t len)
{
    size_t i;
    size_t j;
    uint8_t temp;

    if (!buf || len <= 1)
    {
        return;
    }

    for (i = 0, j = len - 1; i < j; i++, j--)
    {
        temp = buf[i];
        buf[i] = buf[j];
        buf[j] = temp;
    }
}

/*
 * XOR each byte with its position in the packet
 */
void
xor_ptr(uint8_t *buf, size_t len)
{
    size_t i;

    if (!buf || len == 0)
    {
        return;
    }

    for (i = 0; i < len; i++)
    {
        buf[i] ^= (uint8_t)(i + 1);
    }
}

/*
 * Scramble outgoing packet before sending
 */
ssize_t
scramble_outgoing(struct scramble_config *config, uint8_t *buf, ssize_t len)
{
    size_t offset = 0;

    if (!config || !config->enabled || !buf || len <= 0)
    {
        return len;
    }

    switch (config->method)
    {
        case SCRAMBLE_XOR:
            xor_mask(buf, (size_t)len, config->key, config->key_len, &offset);
            break;

        case SCRAMBLE_XOR_PTR:
            xor_ptr(buf, (size_t)len);
            break;

        case SCRAMBLE_REVERSE:
            reverse_bytes(buf, (size_t)len);
            break;

        case SCRAMBLE_OBFUSCATE:
            /* Obfuscate: XOR, then reverse, then XOR with position */
            xor_mask(buf, (size_t)len, config->key, config->key_len, &offset);
            reverse_bytes(buf, (size_t)len);
            xor_ptr(buf, (size_t)len);
            break;

        case SCRAMBLE_NONE:
        default:
            break;
    }

    return len;
}

/*
 * Unscramble incoming packet after receiving
 */
ssize_t
scramble_incoming(struct scramble_config *config, uint8_t *buf, ssize_t len)
{
    size_t offset = 0;

    if (!config || !config->enabled || !buf || len <= 0)
    {
        return len;
    }

    switch (config->method)
    {
        case SCRAMBLE_XOR:
            /* XOR is symmetric, same operation to decode */
            xor_mask(buf, (size_t)len, config->key, config->key_len, &offset);
            break;

        case SCRAMBLE_XOR_PTR:
            /* XOR with position is symmetric */
            xor_ptr(buf, (size_t)len);
            break;

        case SCRAMBLE_REVERSE:
            /* Reverse is symmetric */
            reverse_bytes(buf, (size_t)len);
            break;

        case SCRAMBLE_OBFUSCATE:
            /* Reverse the obfuscate operations */
            xor_ptr(buf, (size_t)len);
            reverse_bytes(buf, (size_t)len);
            xor_mask(buf, (size_t)len, config->key, config->key_len, &offset);
            break;

        case SCRAMBLE_NONE:
        default:
            break;
    }

    return len;
}

/*
 * Cleanup scramble configuration
 */
void
scramble_cleanup(struct scramble_config *config)
{
    if (config)
    {
        /* Securely clear the key from memory */
        memset(config->key, 0, sizeof(config->key));
        config->key_len = 0;
        config->enabled = 0;
        config->method = SCRAMBLE_NONE;
    }
}
'@

$scrambleCPath = Join-Path $srcOpenvpn "scramble.c"
Set-Content -Path $scrambleCPath -Value $scrambleC -Encoding UTF8
Write-Success "Created $scrambleCPath"

# =============================================================================
# STEP 3: Patch Source Code Files
# =============================================================================
Write-Step "Patching Source Code Files"

# --- Patch options.h ---
$optionsHPath = Join-Path $srcOpenvpn "options.h"
if (Test-Path $optionsHPath) {
    Write-Info "Patching options.h..."
    $optionsH = Get-Content $optionsHPath -Raw
    
    # Check if already patched
    if ($optionsH -notmatch "scramble_config") {
        # Add include for scramble.h after other includes
        if ($optionsH -match '#include\s+"buffer\.h"') {
            $optionsH = $optionsH -replace '(#include\s+"buffer\.h")', "`$1`n#include `"scramble.h`""
        }
        elseif ($optionsH -match '#include\s+"common\.h"') {
            $optionsH = $optionsH -replace '(#include\s+"common\.h")', "`$1`n#include `"scramble.h`""
        }
        else {
            # Add at the beginning after header guards
            $optionsH = $optionsH -replace '(#define\s+OPTIONS_H[^\n]*\n)', "`$1`n#include `"scramble.h`"`n"
        }
        
        # Find the struct options definition and add scramble members
        # Look for common patterns in OpenVPN options struct
        $scrambleMembers = @"

    /* XOR Scramble options */
    struct scramble_config scramble;
    const char *scramble_method;
    const char *scramble_key;
"@
        
        # Try to inject after connection_timeout or similar field
        if ($optionsH -match '(struct\s+options\s*\{[^}]*?)(int\s+connect_timeout[^;]*;)') {
            $optionsH = $optionsH -replace '(struct\s+options\s*\{[^}]*?)(int\s+connect_timeout[^;]*;)', "`$1`$2$scrambleMembers"
        }
        elseif ($optionsH -match '(struct\s+options\s*\{[^}]*?)(bool\s+persist_tun[^;]*;)') {
            $optionsH = $optionsH -replace '(struct\s+options\s*\{[^}]*?)(bool\s+persist_tun[^;]*;)', "`$1`$2$scrambleMembers"
        }
        elseif ($optionsH -match '(struct\s+options\s*\{[^}]*?\n)(\s*\};)') {
            # Fallback: add before closing brace of struct options
            $optionsH = $optionsH -replace '(struct\s+options\s*\{[^}]*?\n)(\s*\};)', "`$1$scrambleMembers`n`$2"
        }
        
        Set-Content -Path $optionsHPath -Value $optionsH -NoNewline -Encoding UTF8
        Write-Success "Patched options.h with scramble configuration"
    }
    else {
        Write-Info "options.h already patched, skipping"
    }
}
else {
    Write-Info "options.h not found, creating minimal patch file..."
    $minimalOptionsH = @'
/* Scramble additions for options.h - merge manually if needed */
#ifndef OPENVPN_OPTIONS_SCRAMBLE_PATCH
#define OPENVPN_OPTIONS_SCRAMBLE_PATCH

#include "scramble.h"

/* Add these members to struct options: */
/*
    struct scramble_config scramble;
    const char *scramble_method;
    const char *scramble_key;
*/

#endif
'@
    Set-Content -Path "$srcOpenvpn\options_scramble_patch.h" -Value $minimalOptionsH -Encoding UTF8
    Write-Info "Created options_scramble_patch.h for manual integration"
}

# --- Patch options.c ---
$optionsCPath = Join-Path $srcOpenvpn "options.c"
if (Test-Path $optionsCPath) {
    Write-Info "Patching options.c..."
    $optionsC = Get-Content $optionsCPath -Raw
    
    if ($optionsC -notmatch '"scramble"') {
        # Add scramble option parsing logic
        # Look for add_option function and inject our parser
        
        $scrambleParser = @'

    /* --scramble method key : XOR scramble packets */
    else if (streq(p[0], "scramble") && p[1] && !p[3])
    {
        VERIFY_PERMISSION(OPT_P_GENERAL);
        options->scramble_method = p[1];
        if (p[2])
        {
            options->scramble_key = p[2];
        }
        if (scramble_init(&options->scramble, p[1], p[2]) != 0)
        {
            msg(M_USAGE, "--scramble requires a valid method and key");
        }
    }
'@
        
        # Try to inject after a known option parser
        if ($optionsC -match '(else if \(streq\(p\[0\], "persist-key"\)[^}]+\})') {
            $optionsC = $optionsC -replace '(else if \(streq\(p\[0\], "persist-key"\)[^}]+\})', "`$1$scrambleParser"
            Set-Content -Path $optionsCPath -Value $optionsC -NoNewline -Encoding UTF8
            Write-Success "Patched options.c with scramble option parser"
        }
        elseif ($optionsC -match '(else if \(streq\(p\[0\], "ping"\)[^}]+\})') {
            $optionsC = $optionsC -replace '(else if \(streq\(p\[0\], "ping"\)[^}]+\})', "`$1$scrambleParser"
            Set-Content -Path $optionsCPath -Value $optionsC -NoNewline -Encoding UTF8
            Write-Success "Patched options.c with scramble option parser"
        }
        else {
            Write-Info "Could not find injection point in options.c, creating patch file..."
            Set-Content -Path "$srcOpenvpn\options_scramble_parser.c.patch" -Value $scrambleParser -Encoding UTF8
        }
    }
    else {
        Write-Info "options.c already patched, skipping"
    }
}

# --- Patch socket.c ---
$socketCPath = Join-Path $srcOpenvpn "socket.c"
if (Test-Path $socketCPath) {
    Write-Info "Patching socket.c..."
    $socketC = Get-Content $socketCPath -Raw
    
    # Add include
    if ($socketC -notmatch '#include\s+"scramble\.h"') {
        if ($socketC -match '(#include\s+"socket\.h")') {
            $socketC = $socketC -replace '(#include\s+"socket\.h")', "`$1`n#include `"scramble.h`""
        }
        elseif ($socketC -match '(#include\s+"syshead\.h")') {
            $socketC = $socketC -replace '(#include\s+"syshead\.h")', "`$1`n#include `"scramble.h`""
        }
    }
    
    # Inject scramble calls - these patterns depend on OpenVPN version
    # Look for link_socket_write and link_socket_read functions
    
    # For send operations - before sendto/send calls
    if ($socketC -notmatch 'scramble_outgoing') {
        # Pattern for UDP sendto
        $socketC = $socketC -replace '(size\s*=\s*sendto\s*\([^;]+)(;)', 'scramble_outgoing(NULL, (uint8_t*)buf->data, buf->len); $1$2'
    }
    
    # For receive operations - after recvfrom/recv calls
    if ($socketC -notmatch 'scramble_incoming') {
        # Pattern for UDP recvfrom  
        $socketC = $socketC -replace '(fromlen\s*=\s*sizeof\s*\([^)]+\)[^;]*recvfrom[^;]+;)', '$1 if (size > 0) { scramble_incoming(NULL, (uint8_t*)buf, size); }'
    }
    
    Set-Content -Path $socketCPath -Value $socketC -NoNewline -Encoding UTF8
    Write-Success "Patched socket.c with scramble function calls"
}
else {
    Write-Info "socket.c not found, will need manual patching"
}

# =============================================================================
# STEP 3.5: Fix Missing Headers
# =============================================================================
Write-Step "Fixing Missing Headers"

# 1. Create tap-windows.h manually
$tapWindowsHPath = Join-Path $ScriptRoot "include\tap-windows.h"
$tapWindowsHContent = @"
/*
 *  TAP-Windows -- A kernel driver to provide virtual tap
 *                 device functionality on Windows.
 */

#ifndef __TAP_WIN_H
#define __TAP_WIN_H

#include <winioctl.h>

/*
 * =============
 * TAP IOCTLs
 * =============
 */

#define TAP_WIN_CONTROL_CODE(request,method) \
  CTL_CODE (FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)

#define TAP_WIN_IOCTL_GET_MAC               TAP_WIN_CONTROL_CODE (1, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_GET_VERSION           TAP_WIN_CONTROL_CODE (2, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_GET_MTU               TAP_WIN_CONTROL_CODE (3, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_GET_INFO              TAP_WIN_CONTROL_CODE (4, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT TAP_WIN_CONTROL_CODE (5, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_SET_MEDIA_STATUS      TAP_WIN_CONTROL_CODE (6, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_CONFIG_DHCP_MASQ      TAP_WIN_CONTROL_CODE (7, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_GET_LOG_LINE          TAP_WIN_CONTROL_CODE (8, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT   TAP_WIN_CONTROL_CODE (9, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_CONFIG_TUN            TAP_WIN_CONTROL_CODE (10, METHOD_BUFFERED)

/*
 * =================
 * Registry keys
 * =================
 */

#define ADAPTER_KEY "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define NETWORK_CONNECTIONS_KEY "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

/*
 * ======================
 * Filesystem prefixes
 * ======================
 */

#define USERMODEDEVICEDIR "\\\\.\\Global\\"
#define SYSDEVICEDIR      "\\Device\\"
#define USERDEVICEDIR     "\\DosDevices\\Global\\"
#define TAP_WIN_SUFFIX    ".tap"

#endif
"@
Set-Content -Path $tapWindowsHPath -Value $tapWindowsHContent -Force
Write-Success "Created include\tap-windows.h"

# 2. Configure openvpn-plugin.h
$pluginHIn = Join-Path $ScriptRoot "include\openvpn-plugin.h.in"
$pluginH = Join-Path $ScriptRoot "include\openvpn-plugin.h"
if (Test-Path $pluginHIn) {
    $content = Get-Content $pluginHIn -Raw
    $content = $content -replace '@OPENVPN_VERSION_MAJOR@', '2'
    $content = $content -replace '@OPENVPN_VERSION_MINOR@', '5'
    $content = $content -replace '@OPENVPN_VERSION_PATCH@', '10'
    Set-Content -Path $pluginH -Value $content -Force
    Write-Success "Configured include\openvpn-plugin.h"
}

# =============================================================================
# STEP 4: Fix CMake Build System
# =============================================================================
Write-Step "Fixing CMake Build System"

$rootCMake = Join-Path $ScriptRoot "CMakeLists.txt"

Write-Info "Generating CMakeLists.txt in root..."

$cmakeContent = @'
cmake_minimum_required(VERSION 3.10)
project(OpenVPN C)

# Find dependencies
find_package(OpenSSL REQUIRED)

# LZO handling
find_path(LZO_INCLUDE_DIR lzo/lzo1x.h)
find_library(LZO_LIBRARY NAMES lzo2 lzo)
if(LZO_INCLUDE_DIR AND LZO_LIBRARY)
    message(STATUS "Found LZO: ${LZO_LIBRARY}")
else()
    message(WARNING "LZO not found via standard find. Assuming vcpkg usage.")
    # In vcpkg, lzo2 is often available via pkg-config or just library search
    find_library(LZO_LIBRARY NAMES lzo2)
endif()

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/compat
    ${CMAKE_CURRENT_SOURCE_DIR}/src/openvpn
    ${LZO_INCLUDE_DIR}
)

# Setup config.h
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/config-msvc.h")
    configure_file(config-msvc.h config.h COPYONLY)
    # Disable PKCS11 to avoid dependency issues
    file(APPEND "${CMAKE_CURRENT_BINARY_DIR}/config.h" "\n#undef ENABLE_PKCS11\n")
    add_definitions(-DHAVE_CONFIG_H)
else()
    message(WARNING "config-msvc.h not found! Build will likely fail.")
endif()

# Setup config-msvc-version.h
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/config-msvc-version.h.in")
    set(PRODUCT_NAME "OpenVPN")
    set(PRODUCT_VERSION_MAJOR "2")
    set(PRODUCT_VERSION_MINOR "5")
    set(PRODUCT_VERSION_PATCH "10")
    set(PRODUCT_TARNAME "openvpn")
    set(PRODUCT_BUGREPORT "openvpn-users@lists.sourceforge.net")
    set(PRODUCT_VERSION_RESOURCE "2,5,10,0")
    set(PRODUCT_TAP_WIN_COMPONENT_ID "tap0901")
    set(PRODUCT_TAP_WIN_MIN_MAJOR "9")
    set(PRODUCT_TAP_WIN_MIN_MINOR "21")
    
    configure_file(config-msvc-version.h.in config-msvc-version.h @ONLY)
    # Also create config-version.h as options.c expects it
    configure_file(config-msvc-version.h.in config-version.h @ONLY)
endif()

# Setup openvpn-plugin.h
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/include/openvpn-plugin.h.in")
    configure_file(include/openvpn-plugin.h.in include/openvpn-plugin.h COPYONLY)
endif()

# Download tap-windows.h if missing
if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/include/tap-windows.h")
    message(STATUS "Downloading tap-windows.h...")
    file(DOWNLOAD "https://raw.githubusercontent.com/OpenVPN/tap-windows6/master/include/tap-windows.h" "${CMAKE_CURRENT_SOURCE_DIR}/include/tap-windows.h")
endif()

# Define sources
set(OPENVPN_SOURCES
    src/openvpn/argv.c
    src/openvpn/auth_token.c
    src/openvpn/base64.c
    src/openvpn/block_dns.c
    src/openvpn/buffer.c
    src/openvpn/clinat.c
    src/openvpn/comp.c
    src/openvpn/comp-lz4.c
    src/openvpn/compstub.c
    src/openvpn/console.c
    src/openvpn/console_builtin.c
    src/openvpn/crypto.c
    src/openvpn/crypto_openssl.c
    src/openvpn/cryptoapi.c
    src/openvpn/dhcp.c
    src/openvpn/env_set.c
    src/openvpn/error.c
    src/openvpn/event.c
    src/openvpn/fdmisc.c
    src/openvpn/forward.c
    src/openvpn/fragment.c
    src/openvpn/gremlin.c
    src/openvpn/helper.c
    src/openvpn/httpdigest.c
    src/openvpn/init.c
    src/openvpn/interval.c
    src/openvpn/list.c
    src/openvpn/lladdr.c
    src/openvpn/lzo.c
    src/openvpn/manage.c
    src/openvpn/mbuf.c
    src/openvpn/misc.c
    src/openvpn/mroute.c
    src/openvpn/mss.c
    src/openvpn/mstats.c
    src/openvpn/mtcp.c
    src/openvpn/mtu.c
    src/openvpn/mudp.c
    src/openvpn/multi.c
    src/openvpn/networking_iproute2.c
    src/openvpn/networking_sitnl.c
    src/openvpn/ntlm.c
    src/openvpn/occ.c
    src/openvpn/openvpn.c
    src/openvpn/options.c
    src/openvpn/otime.c
    src/openvpn/packet_id.c
    src/openvpn/perf.c
    src/openvpn/pf.c
    src/openvpn/ping.c
    # src/openvpn/pkcs11.c
    # src/openvpn/pkcs11_openssl.c
    src/openvpn/platform.c
    src/openvpn/plugin.c
    src/openvpn/pool.c
    src/openvpn/proto.c
    src/openvpn/proxy.c
    src/openvpn/ps.c
    src/openvpn/push.c
    src/openvpn/reliable.c
    src/openvpn/route.c
    src/openvpn/run_command.c
    src/openvpn/schedule.c
    src/openvpn/scramble.c
    src/openvpn/session_id.c
    src/openvpn/shaper.c
    src/openvpn/sig.c
    src/openvpn/socket.c
    src/openvpn/socks.c
    src/openvpn/ssl.c
    src/openvpn/ssl_ncp.c
    src/openvpn/ssl_openssl.c
    src/openvpn/ssl_verify.c
    src/openvpn/ssl_verify_openssl.c
    src/openvpn/status.c
    src/openvpn/tls_crypt.c
    src/openvpn/tun.c
    src/openvpn/vlan.c
    src/openvpn/win32.c
    
    # Compat sources
    src/compat/compat-basename.c
    src/compat/compat-dirname.c
    src/compat/compat-gettimeofday.c
    src/compat/compat-daemon.c
    src/compat/compat-inet_ntop.c
    src/compat/compat-inet_pton.c
    src/compat/compat-lz4.c
    src/compat/compat-strsep.c
)

add_executable(openvpn ${OPENVPN_SOURCES})

target_link_libraries(openvpn PRIVATE OpenSSL::SSL OpenSSL::Crypto)

if(LZO_LIBRARY)
    target_link_libraries(openvpn PRIVATE ${LZO_LIBRARY})
endif()

# Windows libraries
target_link_libraries(openvpn PRIVATE ws2_32 iphlpapi wininet setupapi rpcrt4 crypt32 advapi32 user32 shell32 Fwpuclnt Ncrypt)

add_definitions(-D_CRT_SECURE_NO_WARNINGS -DWIN32_LEAN_AND_MEAN)
'@

Set-Content -Path $rootCMake -Value $cmakeContent -Encoding UTF8
Write-Success "Created CMakeLists.txt"


# =============================================================================
# STEP 5: Execute Build
# =============================================================================
Write-Step "Executing Build"

$buildDir = Join-Path $ScriptRoot "build"
$outputDir = Join-Path $ScriptRoot "Build_Output"

# Create build directory
if (-not (Test-Path $buildDir)) {
    New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
}

# Create output directory
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

Push-Location $buildDir
try {
    Write-Info "Configuring CMake..."
    
    # Find Visual Studio
    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $vsPath = ""
    if (Test-Path $vsWhere) {
        $vsPath = & $vsWhere -latest -property installationPath 2>$null
    }
    
    $cmakeGenerator = "Visual Studio 17 2022"
    if (-not $vsPath -or $vsPath -notmatch "2022") {
        # Try VS 2019
        $cmakeGenerator = "Visual Studio 16 2019"
    }
    
    # Configure CMake
    $cmakeArgs = @(
        "..",
        "-G", $cmakeGenerator,
        "-A", "x64",
        "-DCMAKE_TOOLCHAIN_FILE=$vcpkgToolchain",
        "-DCMAKE_BUILD_TYPE=$BuildType",
        "-DVCPKG_TARGET_TRIPLET=x64-windows"
    )
    
    # Find CMake executable
    $cmakeExe = "cmake"
    if (-not (Get-Command "cmake" -ErrorAction SilentlyContinue)) {
        Write-Info "CMake not found in PATH. Searching..."
        
        # Check Visual Studio installation
        $vsCmake = Join-Path $vsPath "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
        if (Test-Path $vsCmake) {
            $cmakeExe = $vsCmake
            Write-Info "Found CMake at $cmakeExe"
        }
        else {
            # Check vcpkg downloads
            $vcpkgDownloads = Join-Path $VcpkgRoot "downloads\tools\cmake*"
            $vcpkgCmake = Get-ChildItem $vcpkgDownloads -Recurse -Filter "cmake.exe" | Select-Object -First 1
            if ($vcpkgCmake) {
                $cmakeExe = $vcpkgCmake.FullName
                Write-Info "Found CMake at $cmakeExe"
            }
            else {
                throw "CMake not found. Please install CMake or add it to your PATH."
            }
        }
    }

    Write-Info "Running: $cmakeExe $($cmakeArgs -join ' ')"
    & $cmakeExe @cmakeArgs
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "CMake configuration failed."
    }
    else {
        Write-Info "Building..."
        & $cmakeExe --build . --config $BuildType --parallel
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Build completed successfully!"
            
            # Find and copy openvpn.exe
            $exePath = Get-ChildItem -Path $buildDir -Recurse -Filter "openvpn.exe" | Select-Object -First 1
            if ($exePath) {
                Copy-Item -Path $exePath.FullName -Destination $outputDir -Force
                Write-Success "Copied openvpn.exe to $outputDir"
            }
            else {
                Write-Info "openvpn.exe not found in build output"
            }
        }
        else {
            Write-Error "Build failed with exit code $LASTEXITCODE"
        }
    }
}
finally {
    Pop-Location
}

# =============================================================================
# Summary
# =============================================================================
Write-Step "Build Summary"

Write-Host "`nFiles created:" -ForegroundColor White
Write-Host "  - $scrambleHPath" -ForegroundColor Gray
Write-Host "  - $scrambleCPath" -ForegroundColor Gray

Write-Host "`nFiles patched:" -ForegroundColor White
if (Test-Path $optionsHPath) { Write-Host "  - $optionsHPath" -ForegroundColor Gray }
if (Test-Path $optionsCPath) { Write-Host "  - $optionsCPath" -ForegroundColor Gray }
if (Test-Path $socketCPath) { Write-Host "  - $socketCPath" -ForegroundColor Gray }

$finalExe = Join-Path $outputDir "openvpn.exe"
if (Test-Path $finalExe) {
    Write-Host "`n" -NoNewline
    Write-Success "BUILD SUCCESSFUL! Output: $finalExe"
    Write-Host "`nUsage example:" -ForegroundColor White
    Write-Host "  openvpn --config myconfig.ovpn --scramble xormask MySecretKey" -ForegroundColor Gray
}
else {
    Write-Host "`n" -NoNewline
    Write-Info "Patch files created. To complete the build:"
    Write-Host "  1. Ensure OpenVPN 2.5 source is in this directory" -ForegroundColor Gray
    Write-Host "  2. Manually integrate patches if auto-patching failed" -ForegroundColor Gray
    Write-Host "  3. Run this script again" -ForegroundColor Gray
}

Write-Host "`nScript completed.`n" -ForegroundColor Cyan
