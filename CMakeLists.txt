cmake_minimum_required(VERSION 3.21)

project(practica VERSION 1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(MIDL_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated/rpc")
file(MAKE_DIRECTORY "${MIDL_OUTPUT_DIR}")

add_custom_command(
    OUTPUT
        "${MIDL_OUTPUT_DIR}/practica_rpc.h"
        "${MIDL_OUTPUT_DIR}/practica_rpc_c.c"
        "${MIDL_OUTPUT_DIR}/practica_rpc_s.c"
    COMMAND midl
        /nologo
        /env x64
        /char signed
        /out "${MIDL_OUTPUT_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/rpc/practica_rpc.idl"
    DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/rpc/practica_rpc.idl"
    VERBATIM
)

add_library(practica_rpc STATIC
    "${MIDL_OUTPUT_DIR}/practica_rpc_c.c"
    "${MIDL_OUTPUT_DIR}/practica_rpc_s.c"
    src/rpc_memory.cpp
)

target_include_directories(practica_rpc PUBLIC
    "${MIDL_OUTPUT_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

add_executable(practica WIN32
    src/gui_main.cpp
    src/service_client.cpp
)

add_executable(practica_service WIN32
    src/av_engine.cpp
    src/service_main.cpp
    src/service_backend.cpp
    src/session_launcher.cpp
)

target_compile_definitions(practica PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_compile_definitions(practica_service PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_compile_options(practica PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /permissive->
)

target_compile_options(practica_service PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /EHsc /permissive->
)

target_link_libraries(practica PRIVATE
    practica_rpc
    user32
    shell32
    advapi32
    rpcrt4
)

target_link_libraries(practica_service PRIVATE
    practica_rpc
    advapi32
    bcrypt
    rpcrt4
    wtsapi32
    userenv
    winhttp
)

target_include_directories(practica PRIVATE
    "${MIDL_OUTPUT_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

target_include_directories(practica_service PRIVATE
    "${MIDL_OUTPUT_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

set_target_properties(practica PROPERTIES
    OUTPUT_NAME "practica"
)

set_target_properties(practica_service PROPERTIES
    OUTPUT_NAME "practica_service"
)

install(TARGETS practica practica_service RUNTIME DESTINATION .)
