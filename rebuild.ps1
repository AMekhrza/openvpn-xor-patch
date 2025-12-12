$buildDir = "D:\Projects\openvpn3\build"
$outputDir = "D:\Projects\openvpn3\Build_Output"
$BuildType = "Release"

# Find Visual Studio
$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsPath = ""
if (Test-Path $vsWhere) {
    $vsPath = & $vsWhere -latest -property installationPath 2>$null
}

# Find CMake executable
$cmakeExe = "cmake"
if (-not (Get-Command "cmake" -ErrorAction SilentlyContinue)) {
    Write-Host "CMake not found in PATH. Searching..."
    
    # Check Visual Studio installation
    $vsCmake = Join-Path $vsPath "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
    if (Test-Path $vsCmake) {
        $cmakeExe = $vsCmake
        Write-Host "Found CMake at $cmakeExe"
    }
    else {
        throw "CMake not found."
    }
}

Write-Host "Building..."
& $cmakeExe --build $buildDir --config $BuildType --parallel

if ($LASTEXITCODE -eq 0) {
    Write-Host "Build completed successfully!"
    
    # Find and copy openvpn.exe
    $exePath = Get-ChildItem -Path $buildDir -Recurse -Filter "openvpn.exe" | Select-Object -First 1
    if ($exePath) {
        Copy-Item -Path $exePath.FullName -Destination $outputDir -Force
        Write-Host "Copied openvpn.exe to $outputDir"
    }
}
else {
    Write-Error "Build failed with exit code $LASTEXITCODE"
}
