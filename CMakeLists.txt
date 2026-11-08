cmake_minimum_required(VERSION 3.14)
project(gtpu_inspector CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra)

add_library(core src/gtpu.cpp src/pcap.cpp)
add_executable(gtpu_tool src/main.cpp)
target_link_libraries(gtpu_tool core)

enable_testing()
add_executable(test_gtpu tests/test_gtpu.cpp)
target_link_libraries(test_gtpu core)
add_test(NAME gtpu COMMAND test_gtpu)
