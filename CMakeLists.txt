cmake_minimum_required(VERSION 3.10)
project(smbios-parser)

if (CMAKE_BUILD_TYPE STREQUAL "")
    message(STATUS "No build type selected, default to 'Release'")
    set(CMAKE_BUILD_TYPE "Release")
endif()

if (UNIX)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wfatal-errors -fvisibility=hidden -Wfatal-errors -pedantic -std=c99 -Wl,--no-undefined -fPIC -Wall -Wextra -Wconversion -Werror=return-type -Werror=incompatible-pointer-types -Werror=sign-compare -Werror=sign-conversion")
    set(CMAKE_C_FLAGS_RELEASE  "${CMAKE_C_FLAGS_RELEASE} -s -O3")
    set(CMAKE_C_FLAGS_DEBUG  "${CMAKE_C_FLAGS_DEBUG} -g -O0")

    set(ENABLE_SANITIZER OFF CACHE BOOL "Enable address sanitizer")
    if (ENABLE_SANITIZER)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
    endif()
endif()

add_library(smbios_static STATIC "smbios.c")
target_include_directories(smbios_static PUBLIC "include")
set_target_properties(smbios_static PROPERTIES
    OUTPUT_NAME "smbios"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    PREFIX "lib" )

add_library(smbios_shared SHARED "smbios.c")
add_compile_definitions(smbios_shared LIB_EXPORT)
target_include_directories(smbios_shared PUBLIC "include")
set_target_properties(smbios_shared PROPERTIES
    OUTPUT_NAME "smbios"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    PREFIX "lib" )

add_executable(smbios_decode "smbios_decode.c")
target_link_libraries(smbios_decode smbios_static)
