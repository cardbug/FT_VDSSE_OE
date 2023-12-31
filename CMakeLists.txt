# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)

if (LVI_MITIGATION MATCHES ControlFlow)
  # Configure the cmake to use customized compilation toolchain.
  # This package has to be added before `project()`.
  find_package(OpenEnclave-LVI-Mitigation CONFIG REQUIRED)
else ()
  # Setting the cmake compiler when LVI mitigation is not enabled. If the CC
  # environment variable has been specified or the if CMAKE_C_COMPILER cmake
  # variable has been passed to cmake, use the C compiler that has been specified.
  # Otherwise, prefer clang. Same for C++ compiler. This must be done before
  # the `project` command.
  if (UNIX)
    if (NOT DEFINED ENV{CC} AND NOT DEFINED CMAKE_C_COMPILER)
      find_program(CMAKE_C_COMPILER clang-11 clang-10 clang)
    endif ()
    if (NOT DEFINED ENV{CXX} AND NOT DEFINED CMAKE_CXX_COMPILER)
      find_program(CMAKE_CXX_COMPILER clang++-11 clang++-10 clang++)
    endif ()
  endif ()
endif ()

project("Hello World Sample" LANGUAGES C CXX)

# Currently the `OpenEnclave` package depends on `project()`.
find_package(OpenEnclave CONFIG REQUIRED)
include_directories("/usr/local/include")
link_directories("/usr/local/lib")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")


# 使用pkg-config来查找grpc和protobuf
find_package(PkgConfig REQUIRED)

pkg_check_modules(GRPC REQUIRED grpc++ grpc)
pkg_check_modules(PROTOBUF REQUIRED protobuf)

#set(Protobuf_LIBRARIES /usr/local/lib/libprotobuf.a)
#set(Protobuf_INCLUDE_DIR /usr/local/include/google/protobuf)
set(CRYPTO_SRC ${OE_CRYPTO_LIB}_src)


# .proto文件的处理
set(PROTOC protoc)
set(GRPC_CPP_PLUGIN grpc_cpp_plugin)
set(GRPC_CPP_PLUGIN_PATH `which ${GRPC_CPP_PLUGIN}`)


set(CMAKE_CXX_STANDARD 11)
set(OE_CRYPTO_LIB
    mbedtls
    CACHE STRING "Crypto library used by enclaves.")

add_subdirectory(enclave)
add_subdirectory(host)

# Generate key
add_custom_command(
  OUTPUT private.pem public.pem
  COMMAND openssl genrsa -out private.pem -3 3072
  COMMAND openssl rsa -in private.pem -pubout -out public.pem)

# Sign enclave
add_custom_command(
  OUTPUT enclave/enclave.signed
  DEPENDS enclave enclave/helloworld.conf private.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:enclave> -c
          ${CMAKE_SOURCE_DIR}/enclave/helloworld.conf -k private.pem)

add_custom_target(sign ALL DEPENDS enclave/enclave.signed)

if ((NOT DEFINED ENV{OE_SIMULATION}) OR (NOT $ENV{OE_SIMULATION}))
  add_custom_target(
    run
    DEPENDS helloworld_host sign
    COMMAND helloworld_host ${CMAKE_BINARY_DIR}/enclave/enclave.signed)
endif ()

add_custom_target(
  simulate
  DEPENDS helloworld_host sign
  COMMAND helloworld_host ${CMAKE_BINARY_DIR}/enclave/enclave.signed --simulate)
