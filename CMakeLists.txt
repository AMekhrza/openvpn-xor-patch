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
