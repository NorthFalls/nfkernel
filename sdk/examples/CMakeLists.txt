cmake_minimum_required(VERSION 3.22)
project(nfkernel_sdk_example LANGUAGES CXX)

# Configure with the NDK toolchain and
# -Dnfkernel_DIR=/path/to/installed/sdk/lib/cmake/nfkernel.
find_package(nfkernel CONFIG REQUIRED)
add_executable(dfm_example basic.cpp)
target_link_libraries(dfm_example PRIVATE nfkernel::sdk)
