# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

find_package(OpenSSL REQUIRED)

# Use the edger8r to generate C bindings from the EDL file.
add_custom_command(
  OUTPUT helloworld_t.h helloworld_t.c helloworld_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/helloworld.edl
  COMMAND
    openenclave::oeedger8r --trusted ${CMAKE_SOURCE_DIR}/helloworld.edl
    --search-path ${OE_INCLUDEDIR} --search-path
    ${OE_INCLUDEDIR}/openenclave/edl/sgx)


set(OE_CRYPTO_LIB
    mbedtls
    CACHE STRING "Crypto library used by enclaves.")

#set(AES_src aes_src)
# ${AES_src}/mbedtls_src.cc
add_executable(enclave enc.cc ${CMAKE_CURRENT_BINARY_DIR}/helloworld_t.c FT_VDSSE.Util.cc ./mbedtls_src/mbedtls_src.cc)

if (WIN32)
  maybe_build_using_clangw(enclave)
endif ()

target_compile_definitions(enclave PUBLIC OE_API_VERSION=2)

# Need for the generated file helloworld_t.h
target_include_directories(enclave PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

if (LVI_MITIGATION MATCHES ControlFlow)
  # Helper to enable compiler options for LVI mitigation.
  apply_lvi_mitigation(enclave)
  # Link against LVI-mitigated libraries.
  target_link_libraries(
    enclave openenclave::oeenclave-lvi-cfg
    openenclave::oecrypto${OE_CRYPTO_LIB}-lvi-cfg 
    openenclave::oelibc-lvi-cfg
    openenclave::oelibcxx
    openenclave::oelibc
    #${OPENSSL_LIBRARIES}
)
else ()
  target_link_libraries(
    enclave openenclave::oeenclave 
    openenclave::oecrypto${OE_CRYPTO_LIB} 
    openenclave::oelibcxx
    openenclave::oelibc
    #${OPENSSL_LIBRARIES}
    )
endif ()
