cmake_minimum_required(VERSION 3.30)
project(ssock LANGUAGES CXX)

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
if(WIN32)
    target_link_libraries(ssock INTERFACE
            ws2_32
            iphlpapi
            dnsapi
    )
else()
    target_link_libraries(ssock INTERFACE
            resolv
    )
endif()
if (APPLE)
    target_link_libraries(ssock INTERFACE
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

if (WIN32)
    target_link_libraries(ssock-build-test
            ws2_32
            iphlpapi
            dnsapi
    )
else()
    target_link_libraries(ssock-build-test
            resolv
    )
endif()
if (APPLE)
    target_link_libraries(ssock-build-test
            "-framework SystemConfiguration"
            "-framework CoreFoundation"
    )
endif()

include_directories(include)