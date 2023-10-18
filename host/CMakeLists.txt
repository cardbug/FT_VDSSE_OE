# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
# 使用pkg-config来查找grpc和protobuf

find_package(Protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)



set(OE_CRYPTO_LIB
    mbedtls
    CACHE STRING "Crypto library used by enclaves.")

add_custom_command(
  OUTPUT helloworld_u.h helloworld_u.c helloworld_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/helloworld.edl
  COMMAND
    openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/helloworld.edl
    --search-path ${OE_INCLUDEDIR} --search-path
    ${OE_INCLUDEDIR}/openenclave/edl/sgx)


add_custom_command(
    OUTPUT FT_VDSSE.pb.cc
    COMMAND ${PROTOC} -I${CMAKE_SOURCE_DIR}/host/ --cpp_out=. ${CMAKE_SOURCE_DIR}/host/FT_VDSSE.proto
    DEPENDS ${CMAKE_SOURCE_DIR}/host/FT_VDSSE.proto
)

add_custom_command(
    OUTPUT FT_VDSSE.grpc.pb.cc
    COMMAND ${PROTOC} -I${CMAKE_SOURCE_DIR}/host/ --grpc_out=. --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN_PATH} ${CMAKE_SOURCE_DIR}/host/FT_VDSSE.proto
    DEPENDS ${CMAKE_SOURCE_DIR}/host/FT_VDSSE.proto
)

add_executable(helloworld_host host.cc ${CMAKE_CURRENT_BINARY_DIR}/helloworld_u.c FT_VDSSE.pb.cc FT_VDSSE.grpc.pb.cc)

if (WIN32)
  copy_oedebugrt_target(helloworld_host_oedebugrt)
  add_dependencies(helloworld_host helloworld_host_oedebugrt)
endif ()

target_include_directories(
  helloworld_host PRIVATE # Needed for the generated file helloworld_u.h
                          ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(helloworld_host 
    openenclave::oehost
    gRPC::grpc++
    gRPC::grpc
    protobuf::libprotobuf
    ${OPENSSL_LIBRARIES}
    #mbedtls
    #openenclave::oecrypto${OE_CRYPTO_LIB} 
    #openenclave::oelibcxx
    #openenclave::oelibc
    )
