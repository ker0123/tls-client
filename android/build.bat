cd /d %~dp0

@REM 需要传入参数, 或者直接修改为 ndk 的实际路径
set NDK=%1

@REM 需要手动修改为实际路径
set OPENSSL_INCLUDE_DIR=D:\scoop\apps\openssl\current\include

set NDK_PROJECT_PATH=.
set APP_BUILD_SCRIPT=Android.mk
set NDK_APPLICATION_MK=Application.mk

%NDK%\ndk-build.cmd ^
NDK_PROJECT_PATH=%NDK_PROJECT_PATH% ^
APP_BUILD_SCRIPT=%APP_BUILD_SCRIPT% ^
NDK_APPLICATION_MK=%NDK_APPLICATION_MK% ^
OPENSSL_INCLUDE_DIR=%OPENSSL_INCLUDE_DIR% ^
V=1

pause