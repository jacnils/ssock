// This is some test code
// It is never compiled in the library, in fact the library is single-header
#include <iostream>
#include <fstream>
#define SSOCK_DEBUG
#include <ssock.hpp>

void basic_socket_connection() {
    const auto ret = ssock::sock::sock_addr("google.com", 80, ssock::sock::sock_addr_type::hostname_ipv4);
    auto sock = ssock::sock::sync_sock(ret, ssock::sock::sock_type::tcp);
    sock.connect();
    sock.send("GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n");
    std::string response = sock.recv(-1);
    std::ofstream file("response.txt");
    file << response;
    file.close();
}

void basic_socket_server() {
    const auto ret = ssock::sock::sock_addr("localhost", 8082, ssock::sock::sock_addr_type::hostname_ipv4);
    auto sock = ssock::sock::sync_sock(ret, ssock::sock::sock_type::tcp);

    sock.bind();
    sock.listen();

    std::cout << "Listening on port 8082..." << std::endl;

    while (true) {
        const auto handle = sock.accept();
        std::string request = sock.recv(-1, handle);
        std::cout << "Received request: " << request << std::endl;
        sock.send("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", handle);
        sock.close(handle);

        break;
    }
}

void basic_socket_connection_ipv6() {
    const auto ret = ssock::sock::sock_addr("google.com", 80, ssock::sock::sock_addr_type::hostname_ipv6);
    auto sock = ssock::sock::sync_sock(ret, ssock::sock::sock_type::tcp);
    sock.connect();
    sock.send("GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n");
    std::string response = sock.recv(-1);
    std::ofstream file("response.txt");
    file << response;
    file.close();
}

void thin_http_abstraction() {
    auto http_abstr = ssock::http::client("forwarderfactory.com", "/api/get_forwarders", 80,
                                         ssock::http::method::GET, ssock::http::version::HTTP_1_1);

    http_abstr.set_connection("Close");
    http_abstr.set_user_agent("ff-wii/1.0");
    http_abstr.set_header("Accept", "application/json");

    const auto& ref = http_abstr.get();
    for (const auto& it : ref.headers) {
        std::cerr << it.first << ": " << it.second << std::endl;
    }
    std::cout << ref.body << std::endl;
}

int main() {
    basic_socket_connection();
    basic_socket_connection_ipv6();
    thin_http_abstraction();
    basic_socket_server();
}