cmake_minimum_required(VERSION 3.26)
project(DseDisable)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)
include("${CMAKE_CURRENT_LIST_DIR}/cmake/global-flags.cmake")

add_subdirectory(km)
add_subdirectory(um)
