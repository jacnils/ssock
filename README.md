# ssock

Simple library for sockets and HTTP in C++.

## Why

Well, first of all, it has zero dependencies whatsoever, so it is equivalent to using your system's exposed C headers.
The problem with these C headers though is that... well, first of all, it's C. We use C++ around here.
Second of all, that brings all the quirks C has with it. Third, while this doesn't as of now support anything but *BSD, Linux and macOS,
it can trivially be extended in the future to support Windows and other operating systems with no rewrites for API users.

It was also just a project made out of a desire to learn the Unix sockets API for fun. Originally I intended to use it as a base
for a wrapper around the Nintendo Wii `network.h` API, but due to how garbage that header is, I temporarily put the project on hold,
polished this up and released it as a standalone library for Unix.

## Features

- Binding, connecting, sending, receiving and closing synchronous sockets
- (Basic) HTTP body parser, including headers and body.
- IPv4 and IPv6 support
- TCP and UDP support
- DNS resolution*
- Network interface enumeration
- Exceptions for errors
- Inheritable classes for easy extension
- C++23
- Support for Windows, Linux, macOS and other Unix-compatible systems.
- No dependencies*

*DNS resolution requires resolv, and you may need to link against it on some systems.

Still missing:

- Server abstraction
- Asynchronous sockets
- SSL/TLS support (would require external dependencies)

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

See `examples/` for examples of how to use the library.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

Copyright (c) 2025 Jacob Nilsson