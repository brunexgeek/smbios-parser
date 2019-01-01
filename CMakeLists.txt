project(dnsblocker)

cmake_minimum_required(VERSION 2.8)

add_library(dmiparser_static STATIC "source/parser.cc")
target_include_directories(dmiparser_static
    PUBLIC "include")
set_target_properties(dmiparser_static PROPERTIES
    OUTPUT_NAME "dmiparser"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    PREFIX "lib" )

add_executable(sample "sample.cc")
target_link_libraries(sample dmiparser_static)
