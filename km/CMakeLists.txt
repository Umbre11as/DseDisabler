project(KernelMode)

add_link_options("/ENTRY:DriverEntry")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
find_package(WDK REQUIRED)

file(GLOB_RECURSE SOURCES "src/*.cpp")

wdk_add_driver(KernelMode ${SOURCES})
