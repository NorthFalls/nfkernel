cmake_minimum_required(VERSION 3.22)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(nfkernel VERSION 2.0 LANGUAGES CXX)
endif()

if(NOT ANDROID OR NOT CMAKE_ANDROID_ARCH_ABI STREQUAL "arm64-v8a")
    message(FATAL_ERROR "Use the Android NDK toolchain with -DANDROID_ABI=arm64-v8a")
endif()
if(ANDROID_NATIVE_API_LEVEL LESS 26)
    message(FATAL_ERROR "Use -DANDROID_PLATFORM=android-26 or newer")
endif()

option(NFKERNEL_BUILD_TOOLS "Build the dfm_loader command-line tool" ON)
option(NFKERNEL_BUILD_EXAMPLE "Build the SDK calling example" ON)

# The kernel ABI is the only source of truth, including in installed SDKs.
configure_file(../abi.h include/dfm/abi.h COPYONLY)

add_library(nfkernel_sdk STATIC src/driver.cpp src/loader.cpp)
add_library(nfkernel::sdk ALIAS nfkernel_sdk)
set_target_properties(nfkernel_sdk PROPERTIES
    EXPORT_NAME sdk
    POSITION_INDEPENDENT_CODE ON
)
target_compile_features(nfkernel_sdk PUBLIC cxx_std_20)
target_compile_options(nfkernel_sdk PRIVATE -Wall -Wextra -Wpedantic)
target_include_directories(nfkernel_sdk PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(nfkernel_sdk PUBLIC log)
# Propagate ELF alignment to tools and external consumers for 16 KiB devices.
target_link_options(nfkernel_sdk INTERFACE "LINKER:-z,max-page-size=16384")

if(NFKERNEL_BUILD_TOOLS)
    add_executable(dfm_loader tools/dfm_loader.cpp)
    target_link_libraries(dfm_loader PRIVATE nfkernel::sdk)
    target_compile_options(dfm_loader PRIVATE -Wall -Wextra -Wpedantic)
    install(TARGETS dfm_loader RUNTIME DESTINATION bin)
endif()
if(NFKERNEL_BUILD_EXAMPLE)
    add_executable(dfm_example examples/basic.cpp)
    target_link_libraries(dfm_example PRIVATE nfkernel::sdk)
    target_compile_options(dfm_example PRIVATE -Wall -Wextra -Wpedantic)
    install(TARGETS dfm_example RUNTIME DESTINATION bin)
endif()

# Self-contained loader: all eight modules are embedded (zlib + XOR) at build
# time, loaded through memfd + finit_module so no .ko ever touches the disk.
option(NFKERNEL_BUILD_NATIVE_LOADER "Build the self-contained NFLoaderDriver" OFF)
set(NFKERNEL_EMBEDDED_HEADER "" CACHE STRING "Directory holding dfm_native_modules.h")
if(NFKERNEL_BUILD_NATIVE_LOADER)
    add_executable(NFLoaderDriver tools/native_loader.cpp)
    target_compile_features(NFLoaderDriver PRIVATE cxx_std_20)
    target_compile_options(NFLoaderDriver PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_definitions(NFLoaderDriver PRIVATE NFKERNEL_EMBEDDED_MODULES=1)
    if(NFKERNEL_EMBEDDED_HEADER)
        target_include_directories(NFLoaderDriver PRIVATE "${NFKERNEL_EMBEDDED_HEADER}")
    endif()
    target_link_libraries(NFLoaderDriver PRIVATE z)
    option(NFKERNEL_USE_MBEDTLS "Link mbedTLS for the HTTPS version check" OFF)
    set(NFKERNEL_MBEDTLS_DIR "" CACHE PATH "mbedTLS source tree")
    if(NFKERNEL_USE_MBEDTLS AND NOT NFKERNEL_MBEDTLS_DIR)
        message(FATAL_ERROR "NFKERNEL_USE_MBEDTLS requires NFKERNEL_MBEDTLS_DIR")
    endif()
    if(NFKERNEL_USE_MBEDTLS)
        set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
        set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
        set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
        add_subdirectory("${NFKERNEL_MBEDTLS_DIR}" third_party/mbedtls)
        target_compile_definitions(NFLoaderDriver PRIVATE NFKERNEL_HTTPS=1)
        target_link_libraries(NFLoaderDriver PRIVATE mbedtls mbedx509 mbedcrypto)
    endif()
    target_link_options(NFLoaderDriver PRIVATE "LINKER:-z,max-page-size=16384")
    install(TARGETS NFLoaderDriver RUNTIME DESTINATION bin)
endif()

include(CMakePackageConfigHelpers)
configure_package_config_file(cmake/nfkernelConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/nfkernelConfig.cmake"
    INSTALL_DESTINATION lib/cmake/nfkernel
)
write_basic_package_version_file("${CMAKE_CURRENT_BINARY_DIR}/nfkernelConfigVersion.cmake"
    VERSION 2.0 COMPATIBILITY SameMajorVersion
)
install(TARGETS nfkernel_sdk EXPORT nfkernelTargets ARCHIVE DESTINATION lib)
install(EXPORT nfkernelTargets NAMESPACE nfkernel:: DESTINATION lib/cmake/nfkernel)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/nfkernelConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/nfkernelConfigVersion.cmake"
    DESTINATION lib/cmake/nfkernel
)
install(DIRECTORY include/dfm DESTINATION include)
install(FILES ../abi.h DESTINATION include/dfm)
install(FILES examples/basic.cpp examples/CMakeLists.txt DESTINATION examples)
