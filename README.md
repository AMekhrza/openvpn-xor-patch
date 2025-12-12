# Custom OpenVPN 2.5 for Windows — XOR Scramble Build

## 1. Project Title
Custom OpenVPN 2.5 for Windows — XOR Scramble Build

## 2. Description
This project is a Windows-focused fork of OpenVPN 2.5 that integrates the Tunnelblick-inspired XOR Scramble obfuscation patch. The added transport mangling hides OpenVPN traffic patterns to help clients bypass deep-packet inspection (DPI) and maintain access to a free, uncensored internet in restrictive regions. The repository includes automation and helper scripts to build, package, and deploy the patched binary on Windows hosts.

## 3. Features
- **XOR Scramble Transport**: The XOR obfuscation module (see `src/openvpn/scramble.c`/`scramble.h`) is wired into OpenVPN's packet pipeline (`src/openvpn/socket.c`, `options.c`, `options.h`) to enable multiple scramble modes such as `obfuscate`, `xorptrpos`, and `reverse`.
- **Automated Build Pipeline**: Running `apply_patch_and_build.ps1` bootstraps vcpkg, applies the scramble patch, configures MSVC via CMake, compiles a Release build, and copies the resulting `openvpn.exe` to `Build_Output/`.
- **Bundled Runtime DLLs**: The `Build_Output/` directory includes the required `libssl-3-x64.dll`, `libcrypto-3-x64.dll`, and `lzo2.dll` so the patched executable can run on clean Windows installations.
- **Deployment Helpers**: Scripts like `Build_Output/setup_openvpn_patch.ps1` and the example profile `Build_Output/test.ovpn` make it easy to install and validate the patched client on target machines.

## 4. Installation & Usage
1. **Clone the repository**
   ```powershell
   git clone https://github.com/AMekhrza/openvpn-xor-patch.git
   cd openvpn-xor-patch
   ```
2. **Run the build script**
   ```powershell
   # PowerShell 7+ recommended
   ./apply_patch_and_build.ps1
   ```
   This installs dependencies via vcpkg (if needed), applies the XOR patch, generates Visual Studio project files, and produces `Build_Output/openvpn.exe`.
3. **Deploy the binary**
   - Manually replace the installed `openvpn.exe` on Windows with the one under `Build_Output/`, or
   - Execute `Build_Output/setup_openvpn_patch.ps1` with administrative privileges to back up and swap binaries automatically.
4. **Enable XOR Scramble in configs**
   Add the scramble directive to your `.ovpn` profile (example in `Build_Output/test.ovpn`):
   ```
   scramble obfuscate MySecretKey
   ```
   Supported methods match the Tunnelblick patch. Ensure both client and server share the same scramble settings.

## 5. Disclaimer & Credits
- This repository is a fork of the official OpenVPN project (https://github.com/OpenVPN/openvpn).
- Original source code copyright: © OpenVPN Inc.
- License: GNU GPL v2, identical to upstream. See `COPYING` and `COPYRIGHT.GPL` for details.
- This software is provided **"AS IS"**, without warranty of any kind. It is intended for educational use and for accessing a free and open internet in restrictive regions. Use responsibly and comply with local laws.
