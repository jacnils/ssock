#include <iostream>
#include <ssock.hpp>

void test_socket() {
    const auto addr = ssock::sock::sock_addr("google.com", 80, ssock::sock::sock_addr_type::hostname);
    auto sock = ssock::sock::sync_sock(addr, ssock::sock::sock_type::tcp);

    sock.connect();
    sock.send("GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n");
    std::string response = sock.recv(-1);
    std::cout << response << std::endl;
}

int main() {
    std::cout << "ssock.hpp" << std::endl;
    test_socket();
}