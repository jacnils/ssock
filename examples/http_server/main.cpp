#include <iostream>
#include <fstream>
#include <ssock.hpp>

int main() {
    ssock::sock::sock_addr addr = {"127.0.0.1", 8080, ssock::sock::sock_addr_type::ipv4};
    ssock::sock::sync_sock sock{addr, ssock::sock::sock_type::tcp, ssock::sock::sock_opt::reuse_addr};

    sock.bind();
    sock.listen(-1);

    while (true) {
        auto client_sock = sock.accept();

        try {
            std::string request = client_sock->recv(-1, "\r\n\r\n");
            std::string response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nHello, World client " + // random identifier
                                   std::to_string(rand() % 1000) + "!\r\n\r\n";
            client_sock->send(response);
            client_sock->close();
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}