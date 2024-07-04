project(smbios-parser)

cmake_minimum_required(VERSION 3.0)

if (UNIX)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wfatal-errors -fvisibility=hidden -Wfatal-errors -pedantic -std=c99 -Wl,--no-undefined -fPIC -Wall -Wextra -Wconversion -Werror=return-type")
    set(CMAKE_C_FLAGS_RELEASE  "${CMAKE_C_FLAGS_RELEASE} -s -O3")
    set(CMAKE_C_FLAGS_DEBUG  "${CMAKE_C_FLAGS_DEBUG} -g -O0")
endif()

add_library(smbios_static STATIC "smbios.c")
target_include_directories(smbios_static
    PUBLIC "include")
set_target_properties(smbios_static PROPERTIES
    OUTPUT_NAME "smbios"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    PREFIX "lib" )

add_executable(smbios_decode "smbios_decode.c")
target_link_libraries(smbios_decode smbios_static)
