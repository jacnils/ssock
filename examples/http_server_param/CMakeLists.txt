cmake_minimum_required(VERSION 3.11)

project(ssock-example LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include_directories(/usr/local/include)

find_package(ssock)

add_executable(
        ssock-example
        main.cpp
)
target_link_libraries(ssock-example PRIVATE
	ssock::ssock
)
