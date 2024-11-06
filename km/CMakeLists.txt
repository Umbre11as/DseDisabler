project(KernelMode)

add_link_options("/ENTRY:DriverEntry")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
find_package(WDK REQUIRED)

file(GLOB_RECURSE SOURCES "src/*.cpp")

wdk_add_driver(KernelMode ${SOURCES})

target_include_directories(KernelMode PRIVATE "thirdparty/Zydis/include")
target_link_libraries(KernelMode "${CMAKE_CURRENT_LIST_DIR}/thirdparty/Zydis/lib/Zydis.lib")

target_include_directories(KernelMode PRIVATE "thirdparty/kCaveHook/include")
target_link_libraries(KernelMode "${CMAKE_CURRENT_LIST_DIR}/thirdparty/kCaveHook/lib/kCaveHook.lib")
