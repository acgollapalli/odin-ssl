powershell -Command "Invoke-WebRequest https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-4.0.0.tar.gz -Outfile libressl-4.0.0.tar.gz"
7z.exe x libressl-4.0.0.tar.gz -so | 7z.exe x -si -ttar
cd libressl-4.0.0
mkdir build-vs2022
cd build-vs2022
set CMAKE_INSTALL_PREFIX=%~dp0%\bindings\lib\windows
@echo %CMAKE_INSTALL_PREFIX%
cmake -G"Visual Studio 17 2022" -DUSE_STATIC_MSVC_RUNTIMES=ON ..
cmake --build . --config Release
cmake --install . --prefix=%CMAKE_INSTALL_PREFIX% --config Release