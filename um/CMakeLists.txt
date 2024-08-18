project(UserMode)

add_subdirectory("thirdparty/Zydis")

file(GLOB_RECURSE SOURCES "src/*.cpp")

add_executable(UserMode ${SOURCES})

target_link_libraries(UserMode PRIVATE Zydis)
