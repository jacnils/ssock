cmake_minimum_required(VERSION 3.30)
project(ssock LANGUAGES CXX)

option(SSOCK_ENABLE_OPENSSL "Enable OpenSSL support in ssock" ON)

add_library(ssock INTERFACE)

set_target_properties(ssock PROPERTIES
        EXPORT_NAME ssock
        INTERFACE_POSITION_INDEPENDENT_CODE ON
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

target_include_directories(ssock
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

if (SSOCK_ENABLE_OPENSSL)
    find_package(OpenSSL QUIET)

    if (NOT OpenSSL_FOUND)
        message(STATUS "Downloading OpenSSL dependency")

        include(FetchContent)
        FetchContent_Declare(
                openssl
                URL https://github.com/openssl/openssl/archive/refs/tags/openssl-3.4.0.tar.gz
        )
        FetchContent_MakeAvailable(openssl)

        add_library(ssock_openssl_crypto INTERFACE)
        add_library(ssock_openssl_ssl INTERFACE)
        target_link_libraries(ssock_openssl_crypto INTERFACE crypto)
        target_link_libraries(ssock_openssl_ssl INTERFACE ssl)

        add_library(OpenSSL::Crypto ALIAS ssock_openssl_crypto)
        add_library(OpenSSL::SSL    ALIAS ssock_openssl_ssl)

        set(OpenSSL_FOUND TRUE)
    endif()

    if (OpenSSL_FOUND)
        message(STATUS "OpenSSL enabled in ssock")
        set(SSOCK_OPENSSL_ENABLED TRUE)
        target_compile_definitions(ssock INTERFACE SSOCK_OPENSSL)
        target_link_libraries(ssock INTERFACE OpenSSL::SSL OpenSSL::Crypto)
    else()
        message(FATAL_ERROR "OpenSSL requested but unavailable.")
    endif()
endif()

if(WIN32)
    target_link_libraries(ssock INTERFACE ws2_32 iphlpapi dnsapi)
elseif(UNIX AND NOT APPLE)
    target_link_libraries(ssock INTERFACE resolv)
endif()
if(APPLE)
    target_link_libraries(ssock INTERFACE
            resolv
            "-framework SystemConfiguration"
            "-framework CoreFoundation"
    )
endif()

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION include
        FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp" PATTERN "*.hxx"
)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/ssockConfigVersion.cmake"
        VERSION 1.0.0
        COMPATIBILITY SameMajorVersion
)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ssockConfig.cmake.in
        "${CMAKE_CURRENT_BINARY_DIR}/ssockConfig.cmake" @ONLY
)

install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/ssockConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/ssockConfigVersion.cmake"
        DESTINATION lib/cmake/ssock
)

install(TARGETS ssock
        EXPORT ssockTargets
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
)

install(EXPORT ssockTargets
        FILE ssockTargets.cmake
        NAMESPACE ssock::
        DESTINATION lib/cmake/ssock
)

add_executable(ssock-build-test test_header.cpp)

if (SSOCK_OPENSSL_ENABLED)
    target_compile_definitions(ssock-build-test PRIVATE SSOCK_OPENSSL)
    target_link_libraries(ssock-build-test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()

if(WIN32)
    target_link_libraries(ssock-build-test PRIVATE ws2_32 iphlpapi dnsapi)
else()
    target_link_libraries(ssock-build-test PRIVATE resolv)
endif()
if(APPLE)
    target_link_libraries(ssock-build-test PRIVATE
            "-framework SystemConfiguration"
            "-framework CoreFoundation"
    )
endif()

include_directories(include)