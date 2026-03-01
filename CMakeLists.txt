cmake_minimum_required (VERSION 3.15)

project(UpdatablePID)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "-O2 -Wall -Wfatal-errors -mavx512f -mavx512dq -mavx512vl")

set(SECUREJOIN_ENABLE_SSE ON CACHE BOOL "" FORCE)

find_package(volePSI REQUIRED HINTS "${CMAKE_SOURCE_DIR}/thirdparty/install/volepsi")
find_package(secureJoin REQUIRED HINTS "${CMAKE_SOURCE_DIR}/thirdparty/install/secure-join")
include("${secureJoin_DIR}/findDependancies.cmake")
include("${secureJoin_DIR}/secureJoinTargets.cmake")

find_package(OpenMP REQUIRED)
# Force OpenSSL from /usr/local/openssl (lib64 layout)
set(OpenSSL_ROOT_DIR "/usr/local/openssl" CACHE PATH "" FORCE)
set(OPENSSL_USE_STATIC_LIBS TRUE CACHE BOOL "" FORCE)

set(OPENSSL_INCLUDE_DIR "/usr/local/openssl/include" CACHE PATH "" FORCE)
set(OPENSSL_CRYPTO_LIBRARY "/usr/local/openssl/lib64/libcrypto.a" CACHE FILEPATH "" FORCE)
set(OPENSSL_SSL_LIBRARY    "/usr/local/openssl/lib64/libssl.a"    CACHE FILEPATH "" FORCE)

find_package(OpenSSL REQUIRED)

message(STATUS "OpenSSL_ROOT_DIR=${OpenSSL_ROOT_DIR}")
message(STATUS "OPENSSL_INCLUDE_DIR=${OPENSSL_INCLUDE_DIR}")
message(STATUS "OPENSSL_LIBRARIES=${OPENSSL_LIBRARIES}")

add_library(Kunlun INTERFACE)
target_include_directories(Kunlun INTERFACE
  "${CMAKE_SOURCE_DIR}/thirdparty/Kunlun"
  "${CMAKE_SOURCE_DIR}/thirdparty/Kunlun/config"
)


target_link_libraries(Kunlun INTERFACE
  OpenMP::OpenMP_CXX
  OpenSSL::Crypto
  OpenSSL::SSL
  dl
)

add_subdirectory(uppid)
add_subdirectory(tests)