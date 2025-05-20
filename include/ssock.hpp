/**
 * @file ssock.hpp
 * @brief A simple TCP/UDP and HTTP socket C++ library for Unix-like systems.
 * @license MIT
 * @author Jacob Nilsson
 * @copyright 2025 Jacob Nilsson
 */
#pragma once

#ifndef SSOCK
#define SSOCK 1
#endif

#ifndef __DEVKITPPC__
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>

#define net_gethostbyname gethostbyname
#define net_connect connect
#define net_socket socket
#define net_send send
#define net_recv recv
#define net_close close
#define net_listen listen
#define net_bind bind
#define net_accept accept
#define net_select select
#else // Nintendo Wii support
#include <network.h>
#endif

#include <string>
#include <sstream>

/**
 * @brief Namespace for the ssock library.
 */
namespace ssock::sock {
    /**
     * @brief Socket address types.
     * @note Use ipv4/ipv6 for IP addresses, and hostname_ipv4/hostname_ipv6 for hostnames, depending on the address type.
     * @note If you are unsure but have a hostname, use hostname_ipv4.
     */
    enum class sock_addr_type {
        ipv4,
        ipv6,
        hostname_ipv4,
        hostname_ipv6,
        hostname = hostname_ipv4,
    };

    /**
     * @brief Socket types.
     */
    enum class sock_type {
        tcp,
        udp,
    };

    /**
     * @brief A struct that contains the IPv4 and IPv6 addresses of a hostname.
     * @note Use resolve_hostname() to get the addresses.
     */
    struct sock_ip_list {
        std::string v4{};
        std::string v6{};
    };

    /**
     * @brief A class that represents a socket handle.
     * @note This class is used internally by the sync_sock class.
     * @note Only useful for binding and accepting connections.
     */
    class sock_handle {
        int sockfd{};
        bool valid{false};
        friend class sync_sock;
    public:
        sock_handle() = default;

        /**
         * @brief Returns true if the socket handle is valid.
         * @return True if the socket handle is valid, false otherwise.
         */
        [[nodiscard]] bool is_valid() const noexcept {
            return valid;
        }

        ~sock_handle() {
            if (valid) {
                net_close(sockfd);
            }
        }
    };

    /**
     * @brief A function that resolves a hostname to an IP address.
     * @param hostname The hostname to resolve.
     * @param port The port to use (default is 80).
     * @return A sock_ip_list struct that contains the IPv4 and IPv6 addresses of the hostname.
     */
    static sock_ip_list resolve_hostname(const std::string& hostname, int port = 80);
    /**
     * @brief A function that checks if a string is a valid IPv4 address.
     * @param ip The string to check.
     * @return True if the string is a valid IPv4 address, false otherwise.
     */
    static bool is_ipv4(const std::string& ip);
    /**
     * @brief A function that checks if a string is a valid IPv6 address.
     * @param ip The string to check.
     * @return True if the string is a valid IPv6 address, false otherwise.
     */
    static bool is_ipv6(const std::string& ip);
    /**
     * @brief A function that checks if a port is valid.
     * @param port The port to check.
     * @return True if the port is valid, false otherwise.
     */
    static bool is_valid_port(int port);

    /**
     * @brief A class that represents a socket address.
     * @param hostname The hostname or IP address to resolve.
     * @param port The port to use.
     * @param t The address type (ipv4, ipv6, hostname_ipv4, hostname_ipv6).
     */
    class sock_addr {
        std::string hostname{};
        std::string ip{};
        int port{};
        sock_addr_type type{sock_addr_type::hostname};
    public:
        /**
         * @brief Constructs a sock_addr object.
         * @param hostname The hostname or IP address to resolve.
         * @param port The port to use.
         * @param t The address type (ipv4, ipv6, hostname_ipv4, hostname_ipv6).
         */
        sock_addr(const std::string& hostname, int port, sock_addr_type t) : port(port) {
            if (t == sock_addr_type::hostname) {
                ip = resolve_hostname(hostname, port).v4;
                this->hostname = hostname;
                if (ip.empty()) {
                    ip = resolve_hostname(hostname, port).v6;
                    type = sock_addr_type::ipv6;
                } else {
                    type = sock_addr_type::ipv4;
                }
            } else if (t == sock_addr_type::hostname_ipv6) {
                ip = resolve_hostname(hostname, port).v6;
                this->hostname = hostname;
                if (ip.empty()) {
                    throw std::runtime_error("sock_addr(): invalid hostname");
                }
                type = sock_addr_type::ipv6;
            } else if (t == sock_addr_type::ipv4 || t == sock_addr_type::ipv6) {
                ip = hostname;
            } else {
                throw std::runtime_error("sock_addr(): invalid address type");
            }

            // validate
            if (this->type == sock_addr_type::ipv4) {
                if (!ssock::sock::is_ipv4(ip)) {
                    throw std::runtime_error("sock_addr(): invalid IPv4 address");
                }
            } else if (this->type == sock_addr_type::ipv6) {
                if (!ssock::sock::is_ipv6(ip)) {
                    throw std::runtime_error("sock_addr(): invalid IPv6 address");
                }
            } else {
                throw std::runtime_error("sock_addr(): invalid address type (validation)");
            }

            if (this->hostname == ip) {
                this->hostname.clear();
            }
        }

        /**
         * @brief Check whether the address is IPv4 or IPv6.
         * @return True if the address is IPv4, false if it is IPv6 or invalid.
         */
        [[nodiscard]] bool is_ipv4() const noexcept {
            return type == sock_addr_type::ipv4;
        }
        /**
         * @brief Check whether the address is IPv6.
         * @return True if the address is IPv6, false if it is IPv4 or invalid.
         */
        [[nodiscard]] bool is_ipv6() const noexcept {
            return type == sock_addr_type::ipv6;
        }
        /**
         * @brief Get the stored IP address.
         * @return The stored IP address.
         * @note Reference
         */
        std::string& get_ip() {
            return this->ip;
        }
        /**
         * @brief Get the stored IP address.
         * @return The stored IP address.
         */
        [[nodiscard]] std::string get_ip() const noexcept {
            return this->ip;
        }
        /**
         * @brief Get the stored hostname.
         * @return The stored hostname.
         * @note Reference
         */
        std::string& get_hostname() {
            if (hostname.empty()) {
                throw std::runtime_error("hostname is empty, use get_ip() instead");
            }
            return hostname;
        }
        /**
         * @brief Get the stored hostname.
         * @return The stored hostname.
         */
        [[nodiscard]] std::string get_hostname() const {
            if (hostname.empty()) {
                throw std::runtime_error("hostname is empty, use get_ip() instead");
            }
            return hostname;
        }
        /**
         * @brief Get the stored port.
         * @return The stored port.
         */
        [[nodiscard]] int get_port() const noexcept {
            return port;
        }
        ~sock_addr() = default;
    };

    class basic_sync_sock {
      public:
        basic_sync_sock() = default;
        virtual ~basic_sync_sock() = 0;
        basic_sync_sock(const basic_sync_sock&) = delete;

        virtual void connect() const = 0;
        virtual void bind() = 0;
        virtual void unbind() = 0;
        virtual void listen(int backlog) const = 0;
        virtual sock_handle accept() = 0;
        virtual int send(const void* buf, size_t len, const sock_handle& h) const = 0;
        virtual int send(const void* buf, size_t len) const = 0;
        virtual void send(const std::string& buf, const sock_handle& h) const = 0;
        virtual void send(const std::string& buf) const = 0;
        [[nodiscard]] virtual std::string recv(int timeout_seconds, const sock_handle& h) const = 0;
        [[nodiscard]] virtual std::string recv_line(const sock_handle& h) const = 0;
        [[nodiscard]] virtual std::string recv(int timeout_seconds) const = 0;
        [[nodiscard]] virtual std::string recv() const = 0;
        [[nodiscard]] virtual std::string recv_line() const = 0;
        virtual void close(const sock_handle& handle) const = 0;
        virtual void close() const = 0;
    };

    /**
     * @brief A class that represents a synchronous socket.
     */
    class sync_sock : private basic_sync_sock {
        sock_addr addr;
        sock_type type{};
        int sockfd{};
        sockaddr_storage sa_storage{};
        bool bound{false};

        [[nodiscard]] const sockaddr* get_sa() const {
            return reinterpret_cast<const sockaddr*>(&sa_storage);
        }

        [[nodiscard]] socklen_t get_sa_len() const {
            if (addr.is_ipv4()) return sizeof(sockaddr_in);
            if (addr.is_ipv6()) return sizeof(sockaddr_in6);
            throw std::runtime_error("Invalid address type");
        }

        void prep_sa() {
            memset(&sa_storage, 0, sizeof(sa_storage));
            if (addr.is_ipv4()) {
                auto* sa4 = reinterpret_cast<sockaddr_in*>(&sa_storage);
                sa4->sin_family = AF_INET;
                sa4->sin_port = htons(addr.get_port());
                if (inet_pton(AF_INET, addr.get_ip().c_str(), &sa4->sin_addr) <= 0) {
                    throw std::runtime_error("Invalid IPv4 address");
                }
            } else if (addr.is_ipv6()) {
                auto* sa6 = reinterpret_cast<sockaddr_in6*>(&sa_storage);
                sa6->sin6_family = AF_INET6;
                sa6->sin6_port = htons(addr.get_port());
                if (inet_pton(AF_INET6, addr.get_ip().c_str(), &sa6->sin6_addr) <= 0) {
                    throw std::runtime_error("Invalid IPv6 address");
                }
            } else {
                throw std::runtime_error("Invalid address type");
            }
        }
    public:
        /**
         * @brief Constructs a sync_sock object.
         * @param addr The socket address to bind to.
         * @param t The socket type (tcp or udp).
         */
        sync_sock(const sock_addr& addr, sock_type t) : addr(addr), type(t) {
            if (addr.get_ip().empty()) {
                throw std::runtime_error("IP address is empty");
            }

            this->sockfd = net_socket(addr.is_ipv4() ? AF_INET : AF_INET6,
                                      t == sock_type::tcp ? SOCK_STREAM : SOCK_DGRAM, 0);

            if (this->sockfd < 0) {
                throw std::runtime_error("failed to create socket");
            }

            this->prep_sa();
        }
        ~sync_sock() override {
            ::net_close(sockfd);
        }
        /**
         * @brief Get the socket address.
         * @return sock_addr& reference
         */
        sock_addr& get_addr() {
            return this->addr;
        }
        /**
         * @brief Get the socket address.
         * @return const sock_addr& reference
         */
        [[nodiscard]] const sock_addr& get_addr() const {
            return this->addr;
        }
        /**
         * @brief Connect the socket to the server.
         */
        void connect() const override {
            if (::net_connect(this->sockfd, this->get_sa(), this->get_sa_len()) < 0) {
                throw std::runtime_error("failed to connect to server");
            }
        }
        /**
         * @brief Bind the socket to the address.
         */
        void bind() override {
            this->bound = true;

            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(this->addr.get_port());

            sockaddr_in6 addr6{};
            addr6.sin6_family = this->addr.is_ipv4() ? AF_INET : AF_INET6;
            addr6.sin6_port = htons(this->addr.get_port());

            if (this->addr.is_ipv4()) {
                addr.sin_addr.s_addr = INADDR_ANY;
                inet_pton(addr.sin_family, this->addr.get_ip().c_str(), &addr.sin_addr);
            } else {
                addr6.sin6_addr = in6addr_any;
                inet_pton(addr6.sin6_family, this->addr.get_ip().c_str(), &addr6.sin6_addr);
            }

            auto ret = ::net_bind(this->sockfd, this->get_sa(), this->get_sa_len());

            if (ret < 0) {
                throw std::runtime_error("failed to bind socket: " + std::to_string(ret));
            }
        }
        /**
         * @brief Unbind the socket from the address.
         */
        void unbind() override {
            if (this->bound) {
                if (::net_close(this->sockfd) < 0) {
                    throw std::runtime_error("failed to unbind socket");
                }
                this->bound = false;
            }
        }
        /**
         * @brief Listen for incoming connections.
         * @param backlog The maximum number of pending connections (default is 5).
         * @note Very barebones, use with care.
         */
        void listen(int backlog) const override {
            if (::net_listen(this->sockfd, backlog) < 0) {
                throw std::runtime_error("failed to listen on socket");
            }
        }
        /**
         * @brief Accept a connection from a client.
         * @return sock_handle The socket handle for the accepted connection.
         */
        [[nodiscard]] sock_handle accept() override {
            sockaddr_storage client_addr{};
            socklen_t addr_len = sizeof(client_addr);

            int client_sockfd = ::net_accept(this->sockfd, reinterpret_cast<sockaddr*>(&client_addr), &addr_len);
            if (client_sockfd < 0) {
                throw std::runtime_error("failed to accept connection");
            }

            sock_handle handle;
            handle.sockfd = client_sockfd;
            handle.valid = true;

            if (bound) {
                this->sockfd = client_sockfd;
            }

            return handle;
        }
        /**
         * @brief Send data to the server.
         * @param buf The data to send.
         * @param len The length of the data.
         * @param h The socket handle to use.
         * @return The number of bytes sent.
         */
        int send(const void* buf, size_t len, const sock_handle& h) const override {
            std::size_t ret = ::net_send((bound && h.is_valid()) ? h.sockfd : this->sockfd, buf, len, 0);
            return static_cast<int>(ret);
        }
        /**
         * @brief Send data to the server.
         * @param buf The data to send.
         * @param len The length of the data.
         * @return The number of bytes sent.
         */
        int send(const void* buf, size_t len) const override {
            return this->send(buf, len, {});
        }
        /**
         * @brief Send a string to the server.
         * @param buf The string to send.
         * @param h The socket handle to use (default is the current socket).
         */
        void send(const std::string& buf, const sock_handle& h) const override {
            static_cast<void>(this->send(buf.c_str(), buf.length(), h));
        }
        /**
         * @brief Send a string to the server.
         * @param buf The string to send.
         */
        void send(const std::string& buf) const override {
            this->send(buf, {});
        }
        /**
         * @brief Receive data from the server.
         * @param timeout_seconds The timeout in seconds (default is -1, which means no timeout).
         * @param h The socket handle to use (default is the current socket).
         * @return The received data as a string.
         */
        [[nodiscard]] std::string recv(const int timeout_seconds, const sock_handle& h) const override {
            std::string data;

            while (true) {
                fd_set readfds;
                FD_ZERO(&readfds);
                FD_SET((bound && h.is_valid()) ? h.sockfd : this->sockfd, &readfds);

                timeval tv{};
                timeval* tv_ptr = nullptr;

                if (timeout_seconds >= 0) {
                    tv.tv_sec = timeout_seconds;
                    tv.tv_usec = 0;
                    tv_ptr = &tv;
                }

                int ret = net_select((bound && h.is_valid()) ? h.sockfd : this->sockfd + 1, &readfds, nullptr, nullptr, tv_ptr);

                if (ret < 0) {
                    throw std::runtime_error("select() failed");
                }
                if (ret == 0) {
                    break;
                }
                if (FD_ISSET(this->sockfd, &readfds)) {
                    char buf[1024];
                    std::size_t received = ::net_recv((bound && h.is_valid()) ? h.sockfd : this->sockfd, buf, sizeof(buf), 0);
                    if (received == 0) {
                        break;
                    }
                    data.append(buf, received);
                }
            }

            return data;
        }
        /**
         * @brief Receive data from the server.
         * @param timeout_seconds The timeout in seconds (default is -1, which means no timeout).
         * @return The received data as a string.
         */
        [[nodiscard]] std::string recv(const int timeout_seconds) const override {
            return this->recv(timeout_seconds, {});
        }
        /**
         * @brief Receive data from the server.
         * @return The received data as a string.
         */
        [[nodiscard]] std::string recv() const override {
            return this->recv(-1, {});
        }
        /**
         * @brief Receive a line of data from the server.
         * @param h The socket handle to use (default is the current socket).
         * @return The received line as a string.
         */
        [[nodiscard]] std::string recv_line(const sock_handle& h) const override {
            std::string line;
            char c;
            while (true) {
                std::size_t ret = ::net_recv((bound && h.is_valid()) ? h.sockfd : this->sockfd, &c, 1, 0);
                if (ret == 0 || c == '\n') {
                    break;
                }
                line += c;
            }
            return line;
        }
        [[nodiscard]] std::string recv_line() const override {
            return this->recv_line({});
        }
        /**
         * @brief Close the socket.
         * @param handle The socket handle to close (default is the current socket).
         */
        void close(const sock_handle& handle) const override {
            if (::net_close((bound && handle.is_valid()) ? handle.sockfd : this->sockfd) < 0) {
                throw std::runtime_error("failed to close socket");
            }
        }
        /**
         * @brief Close the socket.
         */
        void close() const override {
            this->close({});
        }
    };

    static sock_ip_list resolve_hostname(const std::string& hostname, const int port) {
        addrinfo hints{}, *res;

        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        int status = getaddrinfo(hostname.c_str(), std::to_string(port).c_str(), &hints, &res);
        if (status != 0) {
            throw std::runtime_error("resolve_hostname(): function getaddrinfo returned: " + std::string(gai_strerror(status)));
        }

        sock_ip_list list{};

        for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
            char ipstr[INET6_ADDRSTRLEN];

            void* addr{};
            if (p->ai_family == AF_INET) {
                auto* ipv4 = reinterpret_cast<sockaddr_in*>(p->ai_addr);
                addr = &(ipv4->sin_addr);
            } else if (p->ai_family == AF_INET6) {
                auto* ipv6 = reinterpret_cast<sockaddr_in6*>(p->ai_addr);
                addr = &(ipv6->sin6_addr);
            } else {
                freeaddrinfo(res);
                throw std::runtime_error("unknown address family");
            }

            inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
            if (p->ai_family == AF_INET) {
                list.v4 = ipstr;
            } else if (p->ai_family == AF_INET6) {
                list.v6 = ipstr;
            }
        }

        freeaddrinfo(res);

        return list;
    }

    static bool is_ipv4(const std::string& ip) {
        sockaddr_in sa{};
        return inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) != 0;
    }
    static bool is_ipv6(const std::string& ip) {
        sockaddr_in6 sa{};
        return inet_pton(AF_INET6, ip.c_str(), &(sa.sin6_addr)) != 0;
    }
    static bool is_valid_port(const int port) {
        return port > 0 && port <= 65535;
    }
}

/**
 * @brief Namespace for the ssock HTTP library.
 * @note Very basic, could very well be expanded in the future.
 */
namespace ssock::http {
    /**
     * @brief HTTP version.
     */
    enum class version {
        HTTP_1_0,
        HTTP_1_1,
    };
    /**
     * @brief HTTP methods.
     */
    enum class method {
        GET,
        POST,
    };

    /**
     * @brief A struct that represents an HTTP response.
     */
    struct response {
        int status_code{};
        std::string body{};
#ifdef SSOCK_DEBUG
        std::string raw_body{};
#endif
        std::vector<std::pair<std::string, std::string>> headers{};
    };

    /**
     * @brief A function that decodes chunked transfer encoding.
     * @param encoded The encoded string.
     * @return The decoded string.
     */
    static std::string decode_chunked(const std::string& encoded);

    /**
     * @brief Basic HTTP body parser.
     * @note Splits the body into headers and body.
     */
    class basic_body_parser {
        std::string& body;
        response ret{};
    public:
        /**
         * @brief Constructs a basic_body_parser object.
         * @param body The body to parse.
         */
        explicit basic_body_parser(std::string& body) : body(body) {}
        /**
         * @brief Parse the body.
         * @return The parsed response (reference)
         */
        response& parse() {
            ret = response{};
#ifdef SSOCK_DEBUG
            ret.raw_body = body;
#endif
            const auto pos = body.find("\r\n\r\n");
            if (pos == std::string::npos) {
                throw std::runtime_error("no header terminator");
            }
            std::string headers_str = body.substr(0, pos);
            body = body.substr(pos + 4); // skip the \r\n\r\n

            // get status code
            std::istringstream headers_stream(headers_str);
            std::string status_line;
            if (std::getline(headers_stream, status_line)) {
                if (status_line.back() == '\r') status_line.pop_back();
                auto code_pos = status_line.find(' ');
                if (code_pos != std::string::npos) {
                    auto code_end = status_line.find(' ', code_pos + 1);
                    if (code_end != std::string::npos) {
                        try {
                            ret.status_code = std::stoi(status_line.substr(code_pos + 1, code_end - code_pos - 1));
                        } catch (...) {
                            ret.status_code = -1;
                        }
                    }
                }
            }

            // get headers
            std::string line{};
            while (std::getline(headers_stream, line)) {
                if (line.back() == '\r') line.pop_back();
                const auto cpos = line.find(':');
                if (cpos != std::string::npos) {
                    auto key = line.substr(0, cpos);
                    auto value = line.substr(cpos + 1);
                    auto trim = [](std::string& s) {
                        s.erase(0, s.find_first_not_of(" \t"));
                        s.erase(s.find_last_not_of(" \t") + 1);
                    };
                    trim(key);
                    trim(value);
                    ret.headers.emplace_back(key, value);
                }
            }

            // handle chunked
            bool is_enc{false};
            for (const auto& [key, val] : ret.headers) {
                if (key == "Transfer-Encoding" && val.find("chunked") != std::string::npos) {
                    ret.body = std::move(decode_chunked(body));
                    is_enc = true;
                    break;
                }
            }

            if (!is_enc) {
                ret.body = body;
            }

            return ret;
        }
    };

    /**
     * @brief A class that represents an HTTP client.
     */
    class client {
        std::string hostname{};
        std::string path{};
        int port{};
        method m{};
        version v{};

        std::string method_str{};
        std::string version_str{};
        std::vector<std::pair<std::string,std::string>> headers{};
        std::string body{};
        int timeout{-1};

        [[nodiscard]] std::string make_request(const std::string& request) const noexcept {
            ssock::sock::sock_addr addr(hostname, port, ssock::sock::sock_addr_type::hostname_ipv4);
            ssock::sock::sync_sock sock(addr, ssock::sock::sock_type::tcp);
            sock.connect();
            sock.send(request);
            return sock.recv(this->timeout);
        }
    public:
        /**
         * @brief Constructs a client object.
         * @param hostname The hostname to connect to.
         * @param path The path to request.
         * @param port The port to use (default is 80).
         * @param m The HTTP method (GET or POST).
         * @param v The HTTP version (default is HTTP/1.1).
         * @param timeout The timeout in seconds (default is -1, which means no timeout).
         */
        client(const std::string& hostname, const std::string& path, int port, method m, version v = version::HTTP_1_1, int timeout = -1) : hostname(hostname), path(path), port(port), m(m), v(v), timeout(timeout) {
            if (!ssock::sock::is_valid_port(port)) {
                throw std::runtime_error("Invalid port");
            }
            if (hostname.empty()) {
                throw std::runtime_error("Hostname is empty");
            }
            if (path.empty() || path[0] != '/') {
                throw std::runtime_error("path is empty");
            }

            this->method_str = (m == method::GET) ? "GET" : "POST";
            this->version_str = (v == version::HTTP_1_0) ? "HTTP/1.0" : "HTTP/1.1";
        }

        /**
         * @brief Append headers to the request.
         * @param headers The headers to append.
         */
        void append_headers(const std::vector<std::pair<std::string, std::string>>& headers) {
            for (const auto& [key, value] : headers) {
                if (key == "Host" || key == "Content-Length") {
                    throw std::runtime_error("illegal header: " + key);
                }
                this->headers.emplace_back(key, value);
            }
        }
        /**
         * @brief Set the request body.
         * @param body The body to set.
         */
        void set_body(const std::string& body) {
            this->body = body;
        }
        /**
         * @brief Set a header.
         * @param key The header key.
         * @param value The header value.
         */
        void set_header(const std::string& key, const std::string& value) {
            if (key == "Host" || key == "Content-Length") {
                throw std::runtime_error("illegal header: " + key);
            }
            this->headers.emplace_back(key, value);
        }
        /**
         * @brief Set the User-Agent header
         * @param user_agent The User-Agent string to set.
         */
        void set_user_agent(const std::string& user_agent) {
            this->set_header("User-Agent", user_agent);
        }

        /**
         * @brief Set the Content-Type header.
         * @param content_type The Content-Type string to set.
         */
        void set_content_type(const std::string& content_type) {
            this->set_header("Content-Type", content_type);
        }
        /**
         * @brief Set the Accept header.
         * @param accept The Accept string to set.
         * @note Example: "application/json, text/html"
         */
        void set_accept(const std::string& accept) {
            this->set_header("Accept", accept);
        }
        /**
         * @brief Set the Accept-Encoding header.
         * @param accept_encoding The Accept-Encoding string to set.
         * @note Example: "gzip, deflate"
         */
        void set_accept_encoding(const std::string& accept_encoding) {
            this->set_header("Accept-Encoding", accept_encoding);
        }
        /**
         * @brief Set the Accept-Language header.
         * @param accept_language The Accept-Language string to set.
         * @note Example: "en-US,en;q=0.5"
         */
        void set_accept_language(const std::string& accept_language) {
            this->set_header("Accept-Language", accept_language);
        }
        /**
         * @brief Set the Connection header.
         * @param connection The Connection string to set.
         * @note Example: "keep-alive"
         * @note Illegal in HTTP/2, which is not supported by this library.
         */
        void set_connection(const std::string& connection) {
            this->set_header("Connection", connection);
        }
        /**
         * @brief Set the Referer header.
         * @param referer The Referer string to set.
         * @note Example: "https://example.com"
         */
        void set_referer(const std::string& referer) {
            this->set_header("Referer", referer);
        }
        /**
         * @brief Set the Cache-Control header.
         * @param cache_control The Cache-Control string to set.
         * @note Example: "no-cache"
         */
        void set_cache_control(const std::string& cache_control) {
            this->set_header("Cache-Control", cache_control);
        }
        /**
         * @brief Set the Cookie header.
         * @param cookie The Cookie string to set.
         * @note Example: "sessionid=1234567890"
         */
        void set_cookie(const std::string& cookie) {
            this->set_header("Cookie", cookie);
        }
        /**
         * @brief Set the Connect-Timeout header.
         * @param timeout The Connect-Timeout value to set.
         * @note Example: 5
         */
        void set_connect_timeout(int timeout) {
            this->set_header("Connect-Timeout", std::to_string(timeout));
        }
        /**
         * @brief Get the request headers.
         * @return The request headers as a vector of key-value pairs.
         */
        [[nodiscard]] std::vector<std::pair<std::string, std::string>> get_headers() const noexcept {
            return this->headers;
        }
        /**
         * @brief Get the request body.
         * @return The request body as a string.
         */
        [[nodiscard]] std::string get_body() const noexcept {
            return this->body;
        }
        /**
         * @brief Get the request hostname.
         * @return The request hostname as a string.
         */
        [[nodiscard]] std::string get_hostname() const noexcept {
            return this->hostname;
        }
        /**
         * @brief Get the request path.
         * @return The request path as a string.
         */
        [[nodiscard]] std::string get_path() const noexcept {
            return this->path;
        }
        /**
         * @brief Get the request port.
         * @return The request port as an integer.
         */
        [[nodiscard]] int get_port() const noexcept {
            return this->port;
        }
        /**
         * @brief Get the request method.
         * @return The request method as a method enum.
         */
        [[nodiscard]] method get_method() const noexcept {
            return this->m;
        }
        /**
         * @brief Get the request version.
         * @return The request version as a version enum.
         */
        [[nodiscard]] version get_version() const noexcept {
            return this->v;
        }
        /**
         * @brief Get the response from the server.
         * @return response object, parsed.
         */
        [[nodiscard]] response get() const {
            std::string body{};
            body += this->method_str + " " + this->path + " " + this->version_str + "\r\n";

            for (const auto& [key, value] : this->headers) {
                body += key + ": " += value + "\r\n";
            }

            body += "Host: " + this->hostname + "\r\n";

            if (m == method::POST && !this->body.empty()) {
                body += "Content-Length: " + std::to_string(this->body.size()) + "\r\n";
                body += "\r\n" + this->body;
            } else {
                body += "\r\n";
            }

            auto ret = this->make_request(body);
#ifdef SSOCK_DEBUG
            std::ofstream file("response.txt");
            file << ret;
            file.close();
            std::ofstream input("request.txt");
            input << body;
            input.close();
#endif

            basic_body_parser parser{ret};

            return parser.parse();
        }
    };

    static std::string decode_chunked(const std::string& encoded) {
        std::string decoded;
        size_t pos = 0;

        while (pos < encoded.size()) {
            size_t crlf = encoded.find("\r\n", pos);
            if (crlf == std::string::npos) break;

            std::string size_str = encoded.substr(pos, crlf - pos);
            size_t chunk_size = 0;
            try {
                chunk_size = std::stoul(size_str, nullptr, 16);
            } catch (...) {
                break;
            }

            if (chunk_size == 0) break;

            pos = crlf + 2;
            if (pos + chunk_size > encoded.size()) break;

            decoded.append(encoded.substr(pos, chunk_size));
            pos += chunk_size + 2;
        }

        return decoded;
    }
}