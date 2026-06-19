cmake_minimum_required(VERSION 3.27)

project(pseudocode_xrefs LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT DEFINED ENV{IDASDK} OR "$ENV{IDASDK}" STREQUAL "")
  message(FATAL_ERROR "Set IDASDK to the IDA SDK root before configuring.")
endif()

include("$ENV{IDASDK}/src/cmake/bootstrap.cmake")
find_package(idasdk REQUIRED)

ida_add_plugin(pseudocode_xrefs
  SOURCES
    src/pseudocode_xrefs.cpp
  METADATA_JSON
    ida-plugin.json
)

if(WIN32 AND DEFINED ENV{APPDATA})
  set(PSEUDOCODE_XREFS_USER_PLUGIN_DIR
    "$ENV{APPDATA}/Hex-Rays/IDA Pro/plugins/pseudocode_xrefs")

  add_custom_command(TARGET pseudocode_xrefs POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E make_directory
      "${PSEUDOCODE_XREFS_USER_PLUGIN_DIR}"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
      "$<TARGET_FILE:pseudocode_xrefs>"
      "${PSEUDOCODE_XREFS_USER_PLUGIN_DIR}/$<TARGET_FILE_NAME:pseudocode_xrefs>"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
      "${CMAKE_CURRENT_SOURCE_DIR}/ida-plugin.json"
      "${PSEUDOCODE_XREFS_USER_PLUGIN_DIR}/ida-plugin.json"
    COMMENT "Installing Pseudocode Xrefs in the IDA user plugin directory"
  )
endif()

add_executable(pseudocode_xrefs_demo
  demo/pseudocode_xrefs_demo.cpp
)

set_target_properties(pseudocode_xrefs_demo PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/demo"
  RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_SOURCE_DIR}/demo"
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}/demo"
)

if(MSVC)
  target_link_options(pseudocode_xrefs_demo PRIVATE
    "/MAP:${CMAKE_CURRENT_SOURCE_DIR}/demo/pseudocode_xrefs_demo.map"
    "/OPT:NOICF")
endif()
