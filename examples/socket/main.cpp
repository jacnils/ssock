#include <iostream>
#include <fstream>
#include <string_view>
#include <ssock.hpp>

/* The ssock::sock::sync_sock class is modelled to be a more modern variant of Unix
 * sockets. It does not replace them, rather it simply wraps them.
 * The interface is more or less retained with minimal changes. If you know how to
 * use Unix sockets, you will know how to use this class.
 */
int main() {
    /* sock_addr will automatically call resolve_hostname() for DNS resolution.
     * The last parameter is used to determine the address type.
     * type::hostname will resolve the hostname to an IPv6 address if available,
     * otherwise it will resolve to an IPv4 address.
     * If you have an IP address, use type::ipv4 or type::ipv6.
     */
    ssock::sock::sock_addr addr("google.com", 80, ssock::sock::sock_addr_type::hostname);
    /* This will create a socket. It will not bind or connect on its own.
     * You need to call connect() or bind() yourself.
     * The socket type is tcp by default, but you can change it to udp if needed.
     */
    ssock::sock::sync_sock sock(addr, ssock::sock::sock_type::tcp);
    /* This will connect to the server. It will throw an exception if it fails.
     * You can also use bind() to bind the socket to a local address.
     */
    sock.connect();
    /* Here's a simple HTTP request body I crafted for you. The socket API (obviously) doesn't implement any HTTP specifics. */
    constexpr std::string_view request = "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n";
    /* This will send the request to the server. It will throw an exception if it fails.
     * You can also use send() to send data to the server.
     */
    sock.send(request.data());
    /* This will receive the response from the server. It will throw an exception if it fails.
     * You can also use recv() to receive data from the server.
     * The timeout is set to -1, which means no timeout. You can change it to a positive value if needed.
     */
    std::string response = sock.recv(-1).data;
    /* This will close the connection. This will be done automatically for you by the destructor, but I'm
     * calling it manually here just to show that it can be manually invoked if needed.
     */
    sock.close();

    /* Now simply write it to file */
    std::ofstream file("response.txt");
    if (file.is_open()) {
        file << response;
        file.close();
    } else {
        std::cerr << "Failed to open file" << std::endl;
    }
    std::cout << "Response written to response.txt" << std::endl;
}
