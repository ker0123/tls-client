# CMake 配置文件

## 版本信息

cmake_minimum_required(VERSION 3.10)
project(avatr-tls)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

## 查找 OpenSSL

find_package(OpenSSL REQUIRED)

## 最终目标

add_library(tlsclient STATIC src/tlsclient.cpp)

### 最终目标的头文件

target_include_directories(tlsclient PUBLIC src)

### 最终目标的库文件

target_link_libraries(tlsclient PUBLIC
	OpenSSL::SSL
	OpenSSL::Crypto
	ws2_32
	crypt32
	advapi32
)

## 测试目标

add_executable(test test/main.cpp)

## 测试目标直接依赖主目标, 继承主目标的头文件和库依赖

target_link_libraries(test PRIVATE tlsclient)