project(dnsblocker)

cmake_minimum_required(VERSION 2.8)

if (UNIX)
    set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -Wfatal-errors -fvisibility=hidden -Wfatal-errors -pedantic -std=c++98 -Wl,--no-undefined -fPIC -Wall -Wextra -Wconversion -Werror=int-conversion -Werror=return-type -Werror=implicit-function-declaration -Werror=incompatible-pointer-types -Werror=discarded-qualifiers")
    set(CMAKE_CXX_FLAGS_RELEASE  "${CMAKE_C_FLAGS_RELEASE} -s -O3")
    set(CMAKE_CXX_FLAGS_DEBUG  "${CMAKE_C_FLAGS_DEBUG} -g -O0")
endif()

add_library(smbios_static STATIC "smbios.cc")
target_include_directories(smbios_static
    PUBLIC "include")
set_target_properties(smbios_static PROPERTIES
    OUTPUT_NAME "smbios"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    PREFIX "lib" )

add_executable(sample "sample.cc")
target_link_libraries(sample smbios_static)
