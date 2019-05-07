project(dnsblocker)

cmake_minimum_required(VERSION 2.8)

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
