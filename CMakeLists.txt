cmake_minimum_required(VERSION 3.21)

project(practica VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(practica WIN32
    src/main.cpp
)

target_compile_definitions(practica PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_compile_options(practica PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /permissive->
)

target_link_libraries(practica PRIVATE
    user32
    shell32
)

set_target_properties(practica PROPERTIES
    OUTPUT_NAME "practica"
)

install(TARGETS practica RUNTIME DESTINATION .)
