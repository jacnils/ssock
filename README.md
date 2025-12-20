# ssock

[![CMake on Linux, macOS, and Windows](https://github.com/jacnils/ssock/actions/workflows/cmake-multi-platform.yml/badge.svg)](https://github.com/jacnils/ssock/actions/workflows/cmake-multi-platform.yml)

Simple library providing modernized, safe Unix-style sockets, HTTP abstraction, DNS resolution and more for Windows, macOS, Linux and other systems.

## Features

- Binding, connecting, sending, receiving and closing synchronous sockets
- HTTP/1.0 and HTTP/1.1 body parser, including headers and body.
- IPv4 and IPv6 support
- TCP and UDP support
- OpenSSL integration
- DNS resolution*
- Network interface enumeration
- Exceptions for errors
- Inheritable classes for easy extension
- C++23
- Support for Windows, Linux, macOS and other Unix-compatible systems.
- No dependencies\*

\*aside from system level dependencies, which are usually already installed on most systems, and OpenSSL (if enabled).

Still missing:

- Asynchronous sockets

## Dependencies

- C++23 compiler
- CMake

## Building

```bash
mkdir -p build/; cd build/
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
cmake --install .
```

## Usage

You can use the library by simply copying the header into your project. If you do this, make sure to link with:

- Windows: `ws2_32 iphlpapi dnsapi`
- Linux: None.
- macOS: `-framework SystemConfiguration -framework CoreFoundation`

If OpenSSL is desired, link with `ssl` as well.

If deprecated features are enabled (disabled by default), if on Linux or macOS, link with `resolv` as well. 

Alternatively, if you choose to install the library, you can use CMake and link with ssock, which will in turn link with the necessary libraries:

```cmake
...

find_package(ssock)

add_executable(
        MY_TARGET
        main.cpp
)
target_link_libraries(ssock-example PRIVATE
	ssock::ssock
)

...
```

See `examples/` for further examples of how to use the library.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

Copyright (c) 2025 Jacob Nilsson
