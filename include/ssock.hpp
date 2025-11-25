/**
 * @file ssock.hpp
 * @brief A simple TCP/UDP and HTTP socket C++ library for Unix-like systems.
 * @license MIT
 * @author Jacob Nilsson
 * @copyright 2025 Jacob Nilsson
 */
#pragma once

#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>
#include <cstring>
#include <unordered_map>
#include <variant>
#include <algorithm>
#include <ranges>
#include <functional>
#include <random>
#include <filesystem>
#include <thread>
#include <iterator>

#ifndef SSOCK
#define SSOCK 1
#endif

#define SSOCK_FALLBACK_IPV4_DNS_1 "8.8.8.8"
#define SSOCK_FALLBACK_IPV4_DNS_2 "8.8.4.4"
#define SSOCK_FALLBACK_IPV6_DNS_1 "2001:4860:4860::8888"
#define SSOCK_FALLBACK_IPV6_DNS_2 "2001:4860:4860::8844"
#define SSOCK_LOCALHOST_IPV4 "127.0.0.1"
#define SSOCK_LOCALHOST_IPV6 "::1"

#if defined(__APPLE__)
#define SSOCK_MACOS
#include <SystemConfiguration/SystemConfiguration.h>
#endif

#if defined(__unix__) || defined(__unix) || defined(__APPLE__) && defined(__MACH__)
#define SSOCK_UNIX
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#elif _WIN32
#define SSOCK_WINDOWS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windns.h>
#include <iphlpapi.h>
#include <afunix.h>

static constexpr int ns_t_a{1};
static constexpr int ns_t_ns{2};
static constexpr int ns_t_cname{5};
static constexpr int ns_t_soa{6};
static constexpr int ns_t_ptr{12};
static constexpr int ns_t_mx{15};
static constexpr int ns_t_txt{16};
static constexpr int ns_t_aaaa{28};
static constexpr int ns_t_srv{33};
static constexpr int ns_t_any{255};
static constexpr int ns_t_caa{257};

namespace ssock::internal_net {
    inline void ensure_winsock_initialized() {
        static bool initialized = [] {
            WSADATA wsaData;
            int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
            if (result != 0) {
                throw std::runtime_error("WSAStartup failed with code " + std::to_string(result));
            }

            std::atexit([] {
                WSACleanup();
            });

            return true;
        }();
        static_cast<void>(initialized);
    }

    struct winsock_auto_init {
        winsock_auto_init() {
            ssock::internal_net::ensure_winsock_initialized();
        }
    };

    [[maybe_unused]] static winsock_auto_init _winsock_init;
}
#else
#error "Unsupported platform. Please file a pull request to add support for your platform."
#endif

namespace ssock::internal_net {
#if defined(__unix__) || defined(__unix) || defined(__APPLE__) && defined(__MACH__)
    static constexpr auto sys_net_gethostbyname = gethostbyname;
    static constexpr auto sys_net_connect = connect;
    static constexpr auto sys_net_socket = socket;
    static constexpr auto sys_net_send = send;
    static constexpr auto sys_net_recv = recv;
    static constexpr auto sys_net_close = close;
    static constexpr auto sys_net_listen = listen;
    static constexpr auto sys_net_bind = bind;
    static constexpr auto sys_net_accept = accept;
    static constexpr auto sys_net_select = select;
    static constexpr auto sys_net_setsockopt = setsockopt;
#endif
}

namespace ssock {
    using exception_type = std::exception;

    /**
      * @brief A class to represent an exception in a socket operation.
      */
    class socket_error : public exception_type {
        const char* message{"Socket error"};
    public:
        [[nodiscard]] const char* what() const noexcept override {
            return message;
        }
        socket_error() = default;
        explicit socket_error(const char* message) : message(message) {};
        explicit socket_error(const std::string& string) : message(string.c_str()) {};
    };

    /**
      * @brief A class to represent an exception trying to parse.
      */
    class parsing_error : public exception_type {
        const char* message{"Parsing error"};
    public:
        [[nodiscard]] const char* what() const noexcept override {
            return message;
        }
        parsing_error() = default;
        explicit parsing_error(const char* message) : message(message) {};
        explicit parsing_error(const std::string& string) : message(string.c_str()) {};
    };

    /**
      * @brief A class to represent an exception with an IP address.
      */
    class ip_error : public exception_type {
        const char* message{"IP error"};
    public:
        [[nodiscard]] const char* what() const noexcept override {
            return message;
        }
        ip_error() = default;
        explicit ip_error(const char* message) : message(message) {};
        explicit ip_error(const std::string& string) : message(string.c_str()) {};
    };

    /**
      * @brief A class to represent an exception in DNS resolution.
      */
    class dns_error : public exception_type {
        const char* message{"DNS error"};
    public:
        [[nodiscard]] const char* what() const noexcept override {
            return message;
        }
        dns_error() = default;
        explicit dns_error(const char* message) : message(message) {}
        explicit dns_error(const std::string& string) : message(string.c_str()) {};
    };
}

/**
 * @brief Namespace for utility functions and classes.
 * @note Contains helper functions and classes that are not directly related to networking.
 */
namespace ssock::utility {
    /**
     * @brief Splits a string into tokens based on a delimiter.
     * @param str The string to split.
     * @param delimiter The delimiter to use for splitting.
     * @return A vector of strings containing the tokens.
     */
    [[nodiscard]] inline std::vector<std::string> split(const std::string& str, const std::string& delimiter) {
        std::vector<std::string> tokens;
        size_t start = 0;
        size_t end = str.find(delimiter);
        while (end != std::string::npos) {
            tokens.push_back(str.substr(start, end - start));
            start = end + delimiter.length();
            end = str.find(delimiter, start);
        }
        tokens.push_back(str.substr(start, end));
        return tokens;
    }

    /**
     * @brief Joins a vector of strings into a single string with a delimiter.
     * @param tokens The vector of strings to join.
     * @param delimiter The delimiter to use for joining.
     * @return A single string containing the joined tokens.
     */
    [[nodiscard]] inline std::string join(const std::vector<std::string>& tokens, const std::string& delimiter) {
        if (tokens.empty()) return "";
        std::ostringstream oss;
        std::copy(tokens.begin(), tokens.end() - 1, std::ostream_iterator<std::string>(oss, delimiter.c_str()));
        oss << tokens.back();
        return oss.str();
    }
    /**
     * @brief Generates a random alphanumeric string of a given length.
     * @param length The length of the random string to generate.
     * @return A random alphanumeric string.
     */
    [[nodiscard]] static std::string generate_random_string(const std::size_t length = 64) {
        static constexpr char charset[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";

        static constexpr size_t charset_size = sizeof(charset) - 1;
        std::random_device rd;

        std::string result;
        result.reserve(length);

        for (std::size_t i = 0; i < length; ++i) {
            result += charset[rd() % charset_size];
        }

        return result;
    }
    /**
     * @brief URL-encodes a string.
     * @param str The string to encode.
     * @return The URL-encoded string.
     */
    static std::string url_encode(const std::string& str) {
        std::string ret;
        for (int i = 0; i < str.length(); i++) {
            char ch = str[i];
            if (isalnum(ch) || ch == '-' || ch == '_' || ch == '.' || ch == '~') {
                ret += ch;
            } else if (ch == ' ') {
                ret += '+';
            } else {
                ret += '%';
                ret += "0123456789ABCDEF"[ch >> 4];
                ret += "0123456789ABCDEF"[ch & 15];
            }
        }
        return ret;
    }
    /**
     * @brief URL-decodes a string.
     * @param str The string to decode.
     * @return The URL-decoded string.
     */
    static std::string url_decode(const std::string& str) {
        std::string result;
        result.reserve(str.size());

        for (std::size_t i = 0; i < str.length(); ++i) {
            if (str[i] == '%') {
                if (i + 2 < str.length()) {
                    char hex1 = str[i + 1];
                    char hex2 = str[i + 2];

                    if (std::isxdigit(hex1) && std::isxdigit(hex2)) {
                        int high = std::isdigit(hex1) ? hex1 - '0' : std::tolower(hex1) - 'a' + 10;
                        int low  = std::isdigit(hex2) ? hex2 - '0' : std::tolower(hex2) - 'a' + 10;
                        result += static_cast<char>((high << 4) | low);
                        i += 2;
                        continue;
                    }
                }
                result += '%';
            } else if (str[i] == '+') {
                result += ' ';
            } else {
                result += str[i];
            }
        }

        return result;
    }
    static std::unordered_map<std::string, std::string> parse_fields(const std::string& body) {
        std::unordered_map<std::string, std::string> result;

        std::size_t start = 0;
        while (start < body.length()) {
            std::size_t end = body.find('&', start);
            if (end == std::string::npos) end = body.length();

            std::string pair = body.substr(start, end - start);
            std::size_t eq_pos = pair.find('=');

            if (eq_pos != std::string::npos) {
                std::string key = url_decode(pair.substr(0, eq_pos));
                std::string value = url_decode(pair.substr(eq_pos + 1));
                result[std::move(key)] = std::move(value);
            } else if (!pair.empty()) {
                std::string key = url_decode(pair);
                result[std::move(key)] = "";
            }

            start = end + 1;
        }

        return result;
    }
    inline std::string convert_unix_millis_to_gmt(const int64_t unix_millis) {
        if (unix_millis == -1) {
            return "Thu, 01 Jan 1970 00:00:00 GMT";
        }

        std::time_t time = unix_millis / 1000;
        std::tm* tm = std::gmtime(&time);
        char buffer[80];
        std::strftime(buffer, 80, "%a, %d %b %Y %H:%M:%S GMT", tm);
        return {(buffer)};
    }
    [[nodiscard]] inline std::string decode_chunked(const std::string& encoded) {
        std::string dec;
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

            dec.append(encoded.substr(pos, chunk_size));
            pos += chunk_size + 2;
        }

        return dec;
    }

    /**
     * @brief Returns the appropriate content type for a given file name.
     * @param fn The file name to check.
     * @return The content type as a string.
     */
    [[nodiscard]] inline std::string get_appropriate_content_type(const std::string& fn) {
        std::size_t pos = fn.find_last_of('.');
        if (pos == std::string::npos) {
            return "application/octet-stream";
        }

        std::string file = fn.substr(pos);

        static const std::unordered_map<std::string, std::string> content_type_map {
            {".aac", "audio/aac"},
            {".abw", "application/x-abiword"},
            {".apng", "image/apng"},
            {".arc", "application/x-freearc"},
            {".avif", "image/avif"},
            {".avi", "video/x-msvideo"},
            {".azw", "application/vnd.amazon.ebook"},
            {".bin", "application/octet-stream"},
            {".bmp", "image/bmp"},
            {".bz", "application/x-bzip"},
            {".bz2", "application/x-bzip2"},
            {".cda", "application/x-cdf"},
            {".csh", "application/x-csh"},
            {".css", "text/css"},
            {".csv", "text/csv"},
            {".doc", "application/msword"},
            {".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
            {".eot", "application/vnd.ms-fontobject"},
            {".epub", "application/epub+zip"},
            {".gz", "application/gzip"},
            {".gif", "image/gif"},
            {".htm", "text/html"},
            {".html", "text/html"},
            {".ico", "image/vnd.microsoft.icon"},
            {".ics", "text/calendar"},
            {".jar", "application/java-archive"},
            {".jpeg", "image/jpeg"},
            {".jpg", "image/jpeg"},
            {".js", "text/javascript"},
            {".json", "application/json"},
            {".jsonld", "application/ld+json"},
            {".mid", "audio/x-midi"},
            {".midi", "audio/midi"},
            {".mjs", "text/javascript"},
            {".mp3", "audio/mpeg"},
            {".mp4", "video/mp4"},
            {".flac", "audio/flac"},
            {".mpeg", "video/mpeg"},
            {".mpkg", "application/vnd.apple.installer+xml"},
            {".odp", "application/vnd.oasis.opendocument.presentation"},
            {".ods", "application/vnd.oasis.opendocument.spreadsheet"},
            {".odt", "application/vnd.oasis.opendocument.text"},
            {".oga", "audio/ogg"},
            {".ogv", "video/ogg"},
            {".ogx", "application/ogg"},
            {".opus", "audio/ogg"},
            {".otf", "font/otf"},
            {".png", "image/png"},
            {".pdf", "application/pdf"},
            {".php", "application/x-httpd-php"},
            {".ppt", "application/vnd.ms-powerpoint"},
            {".pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
            {".rar", "application/vnd.rar"},
            {".rtf", "application/rtf"},
            {".sh", "application/x-sh"},
            {".svg", "image/svg+xml"},
            {".tar", "application/x-tar"},
            {".tif", "image/tiff"},
            {".tiff", "image/tiff"},
            {".ts", "video/mp2t"},
            {".ttf", "font/ttf"},
            {".txt", "text/plain"},
            {".vsd", "application/vnd.visio"},
            {".wav", "audio/wav"},
            {".weba", "audio/webm"},
            {".webm", "video/webm"},
            {".webp", "image/webp"},
            {".woff", "font/woff"},
            {".woff2", "font/woff2"},
            {".xhtml", "application/xhtml+xml"},
            {".xls", "application/vnd.ms-excel"},
            {".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
            {".xml", "application/xml"},
            {".xul", "application/vnd.mozilla.xul+xml"},
            {".zip", "application/zip"},
            {".3gp", "video/3gpp"},
            {".3g2", "video/3gpp2"},
            {".7z", "application/x-7z-compressed"},
        };

        if (content_type_map.contains(file)) {
            return content_type_map.at(file);
        } else {
            return "application/octet-stream";
        }
    }

    /**
     * @brief Reads the contents of a file into a string.
     * @param path The path to the file.
     */
    [[nodiscard]] static std::string read_file(const std::string& path) {
        std::ifstream file(path, std::ios::in | std::ios::binary | std::ios::ate);
        if (!file) {
            throw std::runtime_error("failed to open file: " + path);
        }

        std::streamsize size = file.tellg();
        std::string buffer(size, '\0');

        file.seekg(0, std::ios::beg);
        if (!file.read(&buffer[0], size)) {
            throw std::runtime_error("failed to read file: " + path);
        }

        return buffer;
    }

    template<typename T>
    static void write(std::ostream& os, const T& val) {
        os.write(reinterpret_cast<const char*>(&val), sizeof(T));
    }

    template<typename T>
    static void read(std::istream& is, T& val) {
        is.read(reinterpret_cast<char*>(&val), sizeof(T));
    }

    static void write_string(std::ostream& os, const std::string& str) {
        auto len = static_cast<uint32_t>(str.size());
        write(os, len);
        os.write(str.data(), len);
    }

    static std::string read_string(std::istream& is) {
        uint32_t len;
        read(is, len);
        std::string str(len, '\0');
        is.read(&str[0], len);
        return str;
    }

    static std::string get_standard_cache_location() {
        const std::string cache_filename = "dns_cache";
        const std::string folder_name = "ssock";

        std::filesystem::path base_path;

#ifdef SSOCK_WINDOWS
        char* appdata = nullptr;
        size_t len = 0;
        _dupenv_s(&appdata, &len, "LOCALAPPDATA");
        if (appdata && *appdata) {
            base_path = appdata;
            free(appdata);
        } else {
            base_path = std::filesystem::temp_directory_path();
        }
        base_path /= folder_name;

#elifdef SSOCK_MACOS
        if (const char* home = std::getenv("HOME")) {
            base_path = std::filesystem::path(home) / "Library" / "Caches" / folder_name;
        } else {
            base_path = std::filesystem::temp_directory_path();
        }

#elifdef SSOCK_UNIX
        const char* xdg = std::getenv("XDG_CACHE_HOME");
        if (xdg) {
            base_path = std::filesystem::path(xdg) / folder_name;
        } else if (const char* home = std::getenv("HOME")) {
            base_path = std::filesystem::path(home) / ".cache" / folder_name;
        } else {
            base_path = std::filesystem::temp_directory_path();  // fallback
        }
#else
#error "Unsupported platform for DNS cache location; write your own derivitive class"
#endif
        std::filesystem::create_directories(base_path);
        return (base_path / cache_filename).string();
    }
}

/**
 * @brief Namespace for the ssock library.
 * @note Contains network-related classes and functions.
 */
namespace ssock::network {
    namespace dns {
        class dns_resolver;
    };

    /**
     * @brief A function that checks if a usable IPv6 address exists.
     * @return True if a usable IPv6 address exists, false otherwise.
     * @note This function checks the local network interfaces for a usable IPv6 address.
     */
    static bool usable_ipv6_address_exists();
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
     * @brief Socket address types.
     * @note Use ipv4/ipv6 for IP addresses, and hostname_ipv4/hostname_ipv6 for hostnames, depending on the address type.
     * @note If you are unsure but have a hostname, use hostname_ipv4.
     */
    enum class sock_addr_type {
        ipv4 = 0, /* IPv4 address */
        ipv6 = 1, /* IPv6 address */
        hostname_ipv4 = 2, /* Hostname; resolve to IPv4 address */
        hostname_ipv6 = 3, /* Hostname; resolve to IPv6 address */
        hostname = 4, /* Hostname; resolve to IPv4 address */
        filename = 5 /* File path; used for Unix domain sockets */
    };

    /**
     * @brief A struct that contains the IPv4 and IPv6 addresses of a hostname.
     * @note Use resolve_hostname() to get the addresses.
     */
    class sock_ip_list final {
    protected:
        std::string v4{};
        std::string v6{};
        friend class sync_sock;
        friend class dns::dns_resolver;
    public:
        explicit sock_ip_list() = default;
        sock_ip_list(std::string v4, std::string v6) : v4(std::move(v4)), v6(std::move(v6)) {}
        [[nodiscard]] bool contains_ipv4() const noexcept {
            return !v4.empty();
        }
        [[nodiscard]] bool contains_ipv6() const noexcept {
            return !v6.empty();
        }
        [[nodiscard]] std::string get_ipv4() const {
            return v4;
        }
        [[nodiscard]] std::string get_ipv6() const {
            return v6;
        }
        [[nodiscard]] std::string get_ip() const {
            return v6.empty() ? v4 : v6;
        }
        static sock_ip_list from_ipv4(const std::string& ip) {
            if (!ssock::network::is_ipv4(ip)) {
                throw ip_error("sock_ip_list::from_ipv4(): invalid IPv4 address");
            }
            return {ip, ""};
        }
        static sock_ip_list from_ipv6(const std::string& ip) {
            if (!ssock::network::is_ipv6(ip)) {
                throw ip_error("sock_ip_list::from_ipv6(): invalid IPv6 address");
            }
            return {"", ip};
        }
        static sock_ip_list from_ip(const std::string& ip) {
            if (ssock::network::is_ipv4(ip)) {
                return sock_ip_list::from_ipv4(ip);
            } else if (ssock::network::is_ipv6(ip)) {
                return sock_ip_list::from_ipv6(ip);
            } else {
                throw ip_error("sock_ip_list::from_ip(): invalid IP address");
            }
        }
        static sock_ip_list from_ips(const std::string& ip_v4, const std::string& ip_v6) {
            if (!ssock::network::is_ipv4(ip_v4) && !ip_v4.empty()) {
                throw ip_error("sock_ip_list::from_ips(): invalid IPv4 address");
            }
            if (!ssock::network::is_ipv6(ip_v6) && !ip_v6.empty()) {
                throw ip_error("sock_ip_list::from_ips(): invalid IPv6 address");
            }
            return {ip_v4, ip_v6};
        }
    };

    class local_ip_address_v4 final {
    protected:
        std::string ip{};
        std::string netmask{};
        std::string broadcast{};
        std::string peer{};
        bool loopback{};
        bool multicast{};
    public:
        local_ip_address_v4() = default;
        local_ip_address_v4(std::string ip, std::string netmask, std::string broadcast, std::string peer, bool loopback, bool multicast)
            : ip(std::move(ip)), netmask(std::move(netmask)), broadcast(std::move(broadcast)), peer(std::move(peer)), loopback(loopback), multicast(multicast) {}

        [[nodiscard]] std::string get_ip() const {
            return ip;
        }
        [[nodiscard]] std::string get_netmask() const {
            return netmask;
        }
        [[nodiscard]] std::string get_broadcast() const {
            return broadcast;
        }
        [[nodiscard]] std::string get_peer() const {
            return peer;
        }
        [[nodiscard]] bool is_loopback() const noexcept {
            return loopback;
        }
        [[nodiscard]] bool is_multicast() const noexcept {
            return multicast;
        }
    };

    class local_ip_address_v6 final {
    protected:
        std::string ip{};
        std::string netmask{};
        bool loopback{};
        bool multicast{};
        bool link_local{};
        std::string scope_id{};
    public:
        local_ip_address_v6() = default;
        local_ip_address_v6(std::string ip, std::string netmask, bool loopback, bool multicast, bool link_local, std::string scope_id)
            : ip(std::move(ip)), netmask(std::move(netmask)), loopback(loopback), multicast(multicast), link_local(link_local), scope_id(std::move(scope_id)) {}

        [[nodiscard]] std::string get_ip() const {
            return ip;
        }
        [[nodiscard]] std::string get_netmask() const {
            return netmask;
        }
        [[nodiscard]] bool is_loopback() const noexcept {
            return loopback;
        }
        [[nodiscard]] bool is_multicast() const noexcept {
            return multicast;
        }
        [[nodiscard]] bool is_link_local() const noexcept {
            return link_local;
        }
        [[nodiscard]] std::string get_scope_id() const {
            return scope_id;
        }
    };

    class network_interface final {
    protected:
        std::vector<local_ip_address_v4> ipv4{};
        std::vector<local_ip_address_v6> ipv6{};
        std::string name{};

        bool up{false};
        bool running{false};
        bool broadcast{false};
        bool point_to_point{false};

        friend std::vector<network_interface> get_interfaces();
    public:
        network_interface() = default;

        [[nodiscard]] const std::vector<local_ip_address_v4>& get_ipv4_addrs() const noexcept {
            return ipv4;
        }
        [[nodiscard]] const std::vector<local_ip_address_v6>& get_ipv6_addrs() const noexcept {
            return ipv6;
        }
        [[nodiscard]] std::string get_name() const {
            return name;
        }
        [[nodiscard]] bool is_up() const noexcept {
            return up;
        }
        [[nodiscard]] bool is_running() const noexcept {
            return running;
        }
        [[nodiscard]] bool is_broadcast() const noexcept {
            return broadcast;
        }
        [[nodiscard]] bool is_point_to_point() const noexcept {
            return point_to_point;
        }
    };

    /**
     * @brief A function that gets the local network interfaces.
     * @return A vector of network_interface structs that contain the local network interfaces.
     */
    inline std::vector<network_interface> get_interfaces();

    namespace dns
    {
        enum class dns_record_type {
            A = 1,
            AAAA = 28,
            CNAME = 5,
            MX = 15,
            NS = 2,
            TXT = 16,
            SOA = 6,
            SRV = 33,
            PTR = 12,
            CAA = 257,
            ANY = 255,
            OTHER = 0,
        };

        struct generic_record_data {
            uint16_t type{};
            std::vector<uint8_t> raw{};
        };

        struct a_record_data {
            sock_ip_list ip{};
        };

        struct aaaa_record_data {
            sock_ip_list ip{};
        };

        struct cname_record_data {
            std::string cname{};
        };

        struct mx_record_data {
            uint16_t preference{};
            std::string exchange{};
        };

        struct ns_record_data {
            std::string ns{};
        };

        struct txt_record_data {
            std::vector<std::string> text{};
        };

        struct soa_record_data {
            std::string mname{};
            std::string rname{};
            uint32_t serial{}, refresh{}, retry{}, expire{}, minimum{};
        };

        struct srv_record_data {
            uint16_t priority{}, weight{}, port{};
            std::string target{};
        };

        struct ptr_record_data {
            std::string ptrname{};
        };

        struct caa_record_data {
            uint8_t flags{};
            std::string tag{};
            std::string value{};
        };

        using dns_record_data = std::variant<
            a_record_data,
            aaaa_record_data,
            cname_record_data,
            mx_record_data,
            ns_record_data,
            txt_record_data,
            soa_record_data,
            srv_record_data,
            ptr_record_data,
            caa_record_data,
            generic_record_data,
            std::monostate
        >;

        inline bool operator==(const a_record_data& lhs, const a_record_data& rhs) {
            return lhs.ip.get_ipv4() == rhs.ip.get_ipv4() && lhs.ip.get_ipv6() == rhs.ip.get_ipv6();
        }

        inline bool operator==(const aaaa_record_data& lhs, const aaaa_record_data& rhs) {
            return lhs.ip.get_ipv4() == rhs.ip.get_ipv4() && lhs.ip.get_ipv6() == rhs.ip.get_ipv6();
        }

        inline bool operator==(const cname_record_data& lhs, const cname_record_data& rhs) {
            return lhs.cname == rhs.cname;
        }

        inline bool operator==(const mx_record_data& lhs, const mx_record_data& rhs) {
            return lhs.preference == rhs.preference && lhs.exchange == rhs.exchange;
        }

        inline bool operator==(const ns_record_data& lhs, const ns_record_data& rhs) {
            return lhs.ns == rhs.ns;
        }

        inline bool operator==(const txt_record_data& lhs, const txt_record_data& rhs) {
            return lhs.text == rhs.text;
        }

        inline bool operator==(const soa_record_data& lhs, const soa_record_data& rhs) {
            return lhs.mname == rhs.mname &&
                   lhs.rname == rhs.rname &&
                   lhs.serial == rhs.serial &&
                   lhs.refresh == rhs.refresh &&
                   lhs.retry == rhs.retry &&
                   lhs.expire == rhs.expire &&
                   lhs.minimum == rhs.minimum;
        }

        inline bool operator==(const srv_record_data& lhs, const srv_record_data& rhs) {
            return lhs.priority == rhs.priority &&
                   lhs.weight == rhs.weight &&
                   lhs.port == rhs.port &&
                   lhs.target == rhs.target;
        }

        inline bool operator==(const ptr_record_data& lhs, const ptr_record_data& rhs) {
            return lhs.ptrname == rhs.ptrname;
        }

        inline bool operator==(const caa_record_data& lhs, const caa_record_data& rhs) {
            return lhs.flags == rhs.flags &&
                   lhs.tag == rhs.tag &&
                   lhs.value == rhs.value;
        }

        inline bool operator==(const generic_record_data& lhs, const generic_record_data& rhs) {
            return lhs.type == rhs.type && lhs.raw == rhs.raw;
        }

        struct dns_record {
            std::string name{};
            dns_record_type type{};
            uint16_t record_class{1};
            uint32_t ttl{};
            dns_record_data data{};
            int64_t created_at{std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()};

            void serialize(std::ostream& os) const {
                utility::write_string(os, name);
                utility::write<uint16_t>(os, static_cast<uint16_t>(type));
                utility::write<uint16_t>(os, record_class);
                utility::write<uint32_t>(os, ttl);
                utility::write<int64_t>(os, created_at);

                std::visit([&]<typename T0>(T0&& val) {
                    using T = std::decay_t<T0>;
                    if constexpr (std::is_same_v<T, a_record_data>) {
                        utility::write<uint8_t>(os, 1);
                        utility::write_string(os, val.ip.get_ip());
                    } else if constexpr (std::is_same_v<T, aaaa_record_data>) {
                        utility::write<uint8_t>(os, 2);
                        utility::write_string(os, val.ip.get_ip());
                    } else if constexpr (std::is_same_v<T, cname_record_data>) {
                        utility::write<uint8_t>(os, 3);
                        utility::write_string(os, val.cname);
                    } else if constexpr (std::is_same_v<T, mx_record_data>) {
                        utility::write<uint8_t>(os, 4);
                        utility::write<uint16_t>(os, val.preference);
                        utility::write_string(os, val.exchange);
                    } else if constexpr (std::is_same_v<T, ns_record_data>) {
                        utility::write<uint8_t>(os, 5);
                        utility::write_string(os, val.ns);
                    } else if constexpr (std::is_same_v<T, txt_record_data>) {
                        utility::write<uint8_t>(os, 6);
                        uint32_t count = val.text.size();
                        utility::write(os, count);
                        for (const auto& s : val.text) {
                            utility::write_string(os, s);
                        }
                    } else if constexpr (std::is_same_v<T, soa_record_data>) {
                        utility::write<uint8_t>(os, 7);
                        utility::write_string(os, val.mname);
                        utility::write_string(os, val.rname);
                        utility::write(os, val.serial);
                        utility::write(os, val.refresh);
                        utility::write(os, val.retry);
                        utility::write(os, val.expire);
                        utility::write(os, val.minimum);
                    } else if constexpr (std::is_same_v<T, srv_record_data>) {
                        utility::write<uint8_t>(os, 8);
                        utility::write(os, val.priority);
                        utility::write(os, val.weight);
                        utility::write(os, val.port);
                        utility::write_string(os, val.target);
                    } else if constexpr (std::is_same_v<T, ptr_record_data>) {
                        utility::write<uint8_t>(os, 9);
                        utility::write_string(os, val.ptrname);
                    } else if constexpr (std::is_same_v<T, caa_record_data>) {
                        utility::write<uint8_t>(os, 10);
                        utility::write(os, val.flags);
                        utility::write_string(os, val.tag);
                        utility::write_string(os, val.value);
                    } else if constexpr (std::is_same_v<T, generic_record_data>) {
                        utility::write<uint8_t>(os, 11);
                        utility::write(os, val.type);
                        utility::write<uint32_t>(os, val.raw.size());
                        os.write(reinterpret_cast<const char*>(val.raw.data()), val.raw.size());
                    } else if constexpr (std::is_same_v<T, std::monostate>) {
                        utility::write<uint8_t>(os, 0);
                    }
                }, data);
            }

            static dns_record deserialize(std::istream& is) {
                dns_record rec;
                rec.name = utility::read_string(is);

                uint16_t type_raw;
                utility::read(is, type_raw);
                rec.type = static_cast<dns_record_type>(type_raw);

                utility::read(is, rec.record_class);
                utility::read(is, rec.ttl);
                utility::read<int64_t>(is, rec.created_at);

                uint8_t tag;
                utility::read(is, tag);

                switch (tag) {
                case 1: {
                        a_record_data a;
                        a.ip = sock_ip_list::from_ipv4(utility::read_string(is));
                        rec.data = a;
                        break;
                }
                case 2: {
                        aaaa_record_data aaaa;
                        aaaa.ip = sock_ip_list::from_ipv6(utility::read_string(is));
                        rec.data = aaaa;
                        break;
                }
                case 3: {
                        cname_record_data c;
                        c.cname = utility::read_string(is);
                        rec.data = c;
                        break;
                }
                case 4: {
                        mx_record_data m;
                        utility::read(is, m.preference);
                        m.exchange = utility::read_string(is);
                        rec.data = m;
                        break;
                }
                case 5: {
                        ns_record_data n;
                        n.ns = utility::read_string(is);
                        rec.data = n;
                        break;
                }
                case 6: {
                        txt_record_data t;
                        uint32_t count;
                        utility::read(is, count);
                        t.text.resize(count);
                        for (auto& s : t.text) {
                            s = utility::read_string(is);
                        }
                        rec.data = t;
                        break;
                }
                case 7: {
                        soa_record_data soa;
                        soa.mname = utility::read_string(is);
                        soa.rname = utility::read_string(is);
                        utility::read(is, soa.serial);
                        utility::read(is, soa.refresh);
                        utility::read(is, soa.retry);
                        utility::read(is, soa.expire);
                        utility::read(is, soa.minimum);
                        rec.data = soa;
                        break;
                }
                case 8: {
                        srv_record_data srv;
                        utility::read(is, srv.priority);
                        utility::read(is, srv.weight);
                        utility::read(is, srv.port);
                        srv.target = utility::read_string(is);
                        rec.data = srv;
                        break;
                }
                case 9: {
                        ptr_record_data p;
                        p.ptrname = utility::read_string(is);
                        rec.data = p;
                        break;
                }
                case 10: {
                        caa_record_data c;
                        utility::read(is, c.flags);
                        c.tag = utility::read_string(is);
                        c.value = utility::read_string(is);
                        rec.data = c;
                        break;
                }
                case 11: {
                        generic_record_data g;
                        utility::read(is, g.type);
                        uint32_t len;
                        utility::read(is, len);
                        g.raw.resize(len);
                        is.read(reinterpret_cast<char*>(g.raw.data()), len);
                        rec.data = g;
                        break;
                }
                case 0:
                default:
                    rec.data = std::monostate{};
                }

                return rec;
            }
        };

        inline bool operator==(const dns_record& lhs, const dns_record& rhs) {
            return lhs.name == rhs.name &&
                   lhs.type == rhs.type &&
                   lhs.record_class == rhs.record_class &&
                   lhs.data == rhs.data;
        }

        namespace deprecated {
            using dns_selector = std::variant<std::monostate, std::string, dns_record_type>;
            class dns_resolver final {
                std::string hostname{};

                void throw_if_invalid() const {
                    if (hostname == "localhost") {
                        return;
                    }
                    if (hostname.empty()) {
                        throw parsing_error("dns_resolver(): hostname cannot be empty");
                    }
                    if (hostname.find('.') == std::string::npos) {
                        throw parsing_error("dns_resolver(): hostname must contain at least one dot (.)");
                    }
                    if (hostname.back() == '.') {
                        throw parsing_error("dns_resolver(): hostname cannot end with a dot (.)");
                    }
                }

                template<typename>
                struct always_false : std::false_type {};

                static int dns_type_from_string(const std::string& type_str) {
                    static const std::unordered_map<std::string, int> type_map = {
                        {"A", ns_t_a},
                        {"AAAA", ns_t_aaaa},
                        {"CNAME", ns_t_cname},
                        {"MX", ns_t_mx},
                        {"NS", ns_t_ns},
                        {"TXT", ns_t_txt},
                        {"SOA", ns_t_soa},
                        {"SRV", ns_t_srv},
                        {"PTR", ns_t_ptr},
                        {"CAA", 257},
                        {"ANY", ns_t_any}
                    };

                    std::string key = type_str;
                    std::ranges::transform(key.begin(), key.end(), key.begin(), ::toupper); // normalize

                    auto it = type_map.find(key);
                    if (it != type_map.end()) return it->second;

                    throw dns_error("dns_type_from_string(): unknown DNS type: " + type_str);
                }

                static int resolve_query_type(const dns_selector& selector) {
                    return std::visit([]<typename T0>(T0&& arg) -> int {
                        using T = std::decay_t<T0>;
                        if constexpr (std::is_same_v<T, std::monostate>) return ns_t_any;
                        else if constexpr (std::is_same_v<T, std::string>) return dns_type_from_string(arg);
                        else if constexpr (std::is_same_v<T, dns_record_type>) {
                            switch (arg) {
                                case dns_record_type::A: return ns_t_a;
                                case dns_record_type::AAAA: return ns_t_aaaa;
                                case dns_record_type::CNAME: return ns_t_cname;
                                case dns_record_type::MX: return ns_t_mx;
                                case dns_record_type::NS: return ns_t_ns;
                                case dns_record_type::TXT: return ns_t_txt;
                                case dns_record_type::SOA: return ns_t_soa;
                                case dns_record_type::SRV: return ns_t_srv;
                                case dns_record_type::PTR: return ns_t_ptr;
                                case dns_record_type::CAA: return 257;
                                default: return ns_t_any;
                            }
                        } else {
                            static_assert(always_false<T>::value, "unhandled selector type");
                        }
                        throw dns_error("resolve_query_type(): unhandled selector type");
                    }, selector);
                }
            public:
                dns_resolver() = default;
                explicit dns_resolver(std::string hostname) : hostname(std::move(hostname)) {
                    throw_if_invalid();
                }
                /**
                 * @brief Set the hostname to resolve.
                 * @param hostname The hostname to resolve.
                 */
                void set_hostname(const std::string& hostname) {
                    this->hostname = hostname;
                    throw_if_invalid();
                }
                /**
                 * @brief Get the hostname to resolve.
                 * @return The hostname to resolve.
                 */
                [[nodiscard]] std::string get_hostname() const {
                    return this->hostname;
                }
                /**
                 * @brief Resolve the hostname to an IP address.
                 * @param port The port to use (default is 80).
                 * @return A sock_ip_list struct that contains the IPv4 and IPv6 addresses of the hostname.
                 */
                [[nodiscard]] sock_ip_list resolve_hostname(const int port = 80) const {
                    addrinfo hints{}, *res;

                    hints.ai_family = AF_UNSPEC;
                    hints.ai_socktype = SOCK_STREAM;

                    int status = getaddrinfo(this->hostname.c_str(), std::to_string(port).c_str(), &hints, &res);
                    if (status != 0) {
                        throw dns_error("resolve_hostname(): getaddrinfo failed: " + std::string(gai_strerror(status)));
                    }

                    std::string v4{};
                    std::string v6{};

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
                            throw dns_error("resolve_hostname(): unknown address family");
                        }

                        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
                        if (p->ai_family == AF_INET) {
                            v4 = ipstr;
                        } else if (p->ai_family == AF_INET6) {
                            v6 = ipstr;
                        }
                    }

                    freeaddrinfo(res);

                    return {std::move(v4), std::move(v6)};
                }
#ifdef SSOCK_UNIX
                [[nodiscard]] std::vector<dns_record> query_records(const dns_selector& selector = std::monostate{}) const {
                    throw_if_invalid();

                    int qtype = resolve_query_type(selector);

                    res_init();

                    u_char response[2048]{};
                    int len = res_query(hostname.c_str(), ns_c_in, qtype, response, sizeof(response));
                    if (len < 0) {
                        if (h_errno == NO_DATA) {
                            return {};
                        }
                        throw dns_error("query_records(): res_query failed: " + std::string(hstrerror(h_errno)));
                    }

                    ns_msg handle;
                    if (len != 0) {
                        if (ns_initparse(response, len, &handle) < 0) {
                            std::string error = "query_records(): DNS response parse failed with error: " + std::string(hstrerror(h_errno));
                            error += ", length: " + std::to_string(len);
                            throw parsing_error("query_records(): DNS response parse failed: " + error);
                        }
                    }

                    std::vector<dns_record> records;
                    int count = ns_msg_count(handle, ns_s_an);

                    for (int i = 0; i < count; ++i) {
                        ns_rr rr;
                        if (ns_parserr(&handle, ns_s_an, i, &rr) != 0) continue;

                        const u_char* rdata = ns_rr_rdata(rr);
                        uint16_t type = ns_rr_type(rr);
                        uint16_t rdlen = ns_rr_rdlen(rr);

                        dns_record rec;
                        rec.name = ns_rr_name(rr);
                        rec.ttl = ns_rr_ttl(rr);
                        rec.type = dns_record_type::OTHER;

                        switch (type) {
                        case ns_t_a: {
                                char ip[INET_ADDRSTRLEN];
                                inet_ntop(AF_INET, rdata, ip, sizeof(ip));
                                rec.type = dns_record_type::A;
                                auto list = sock_ip_list{ip, ""};
                                rec.data = a_record_data{list};
                                break;
                        }
                        case ns_t_aaaa: {
                                char ip[INET6_ADDRSTRLEN];
                                inet_ntop(AF_INET6, rdata, ip, sizeof(ip));
                                rec.type = dns_record_type::AAAA;
                                auto list = sock_ip_list{"", ip};
                                rec.data = aaaa_record_data{list};
                                break;
                        }
                        case ns_t_cname: {
                                char cname[NS_MAXDNAME];
                                ns_name_uncompress(response, response + len, rdata, cname, sizeof(cname));
                                rec.type = dns_record_type::CNAME;
                                rec.data = cname_record_data{cname};
                                break;
                        }
                        case ns_t_txt: {
                                txt_record_data txt;
                                int offset = 0;
                                while (offset < rdlen) {
                                    uint8_t slen = rdata[offset];
                                    txt.text.emplace_back(reinterpret_cast<const char*>(&rdata[offset + 1]), slen);
                                    offset += slen + 1;
                                }
                                rec.type = dns_record_type::TXT;
                                rec.data = txt;
                                break;
                        }
                        default: {
                                std::vector<uint8_t> raw(rdata, rdata + rdlen);
                                rec.data = generic_record_data{type, raw};
                                break;
                        }
                        }

                        records.push_back(std::move(rec));
                    }

                    return records;
                }
#endif
#ifdef SSOCK_WINDOWS
                [[nodiscard]] std::vector<dns_record> query_records(const dns_selector& selector = std::monostate{}) const {
                    throw_if_invalid();

                    WORD qtype = resolve_query_type(selector);

                    PDNS_RECORD pRecord = nullptr;
                    DNS_STATUS status = DnsQuery_A(
                        hostname.c_str(),
                        qtype,
                        DNS_QUERY_STANDARD,
                        nullptr,
                        &pRecord,
                        nullptr
                    );

                    if (status == DNS_INFO_NO_RECORDS || status == DNS_ERROR_RCODE_NAME_ERROR) {
                        return {};
                    }

                    if (status != 0 || pRecord == nullptr) {
                        throw dns_error("query_records(): DnsQuery_A failed with error code: " + std::to_string(status));
                    }

                    std::vector<dns_record> records;

                    for (PDNS_RECORD rec = pRecord; rec != nullptr; rec = rec->pNext) {
                        dns_record result;
                        result.name = rec->pName;
                        result.ttl = rec->dwTtl;
                        result.type = dns_record_type::OTHER;

                        switch (rec->wType) {
                        case DNS_TYPE_A: {
                                char ip[INET_ADDRSTRLEN];
                                inet_ntop(AF_INET, &rec->Data.A.IpAddress, ip, sizeof(ip));
                                result.type = dns_record_type::A;
                                result.data = a_record_data{sock_ip_list{ip, ""}};
                                break;
                        }
                        case DNS_TYPE_AAAA: {
                                char ip[INET6_ADDRSTRLEN];
                                inet_ntop(AF_INET6, rec->Data.AAAA.Ip6Address.IP6Byte, ip, sizeof(ip));
                                result.type = dns_record_type::AAAA;
                                result.data = aaaa_record_data{sock_ip_list{"", ip}};
                                break;
                        }
                        case DNS_TYPE_CNAME: {
                                result.type = dns_record_type::CNAME;
                                result.data = cname_record_data{rec->Data.CNAME.pNameHost};
                                break;
                        }
                        case DNS_TYPE_TEXT: {
                                txt_record_data txt;
                                for (DWORD i = 0; i < rec->Data.TXT.dwStringCount; ++i) {
                                    txt.text.emplace_back(rec->Data.TXT.pStringArray[i]);
                                }
                                result.type = dns_record_type::TXT;
                                result.data = txt;
                                break;
                        }
                        default: {
                                result.data = generic_record_data{rec->wType, {}};
                                break;
                        }
                        }

                        records.push_back(std::move(result));
                    }

                    DnsRecordListFree(pRecord, DnsFreeRecordList);

                    return records;
                }
#endif
            };
        }
    }

    /**
     * @brief Get a list of all network interfaces on the system.
     * @return A vector of network_interface objects.
     * @throws std::runtime_error if getifaddrs() fails.
     */
#ifdef SSOCK_UNIX
    inline std::vector<network_interface> get_interfaces() {
        std::vector<network_interface> list;

        struct ifaddrs* ifaddr;
        if (getifaddrs(&ifaddr) == -1) {
            throw ssock::ip_error{"getifaddrs() failed in get_interfaces()"};
        }

        std::unordered_map<std::string, network_interface> iface_map;

        for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr)
                continue;

            const std::string name(ifa->ifa_name);
            auto& iface = iface_map[name];
            iface.name = name;

            iface.up = (ifa->ifa_flags & IFF_UP);
            iface.running = (ifa->ifa_flags & IFF_RUNNING);
            iface.broadcast = (ifa->ifa_flags & IFF_BROADCAST);
            iface.point_to_point = (ifa->ifa_flags & IFF_POINTOPOINT);

            char addr_buf[INET6_ADDRSTRLEN]{};
            char netmask_buf[INET6_ADDRSTRLEN]{};
            char broadcast_buf[INET_ADDRSTRLEN]{};
            char peer_buf[INET_ADDRSTRLEN]{};

            if (ifa->ifa_addr->sa_family == AF_INET) {
                auto sa = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
                if (!inet_ntop(AF_INET, &(sa->sin_addr), addr_buf, sizeof(addr_buf)))
                    continue;

                if (ifa->ifa_netmask) {
                    auto netmask = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_netmask);
                    inet_ntop(AF_INET, &(netmask->sin_addr), netmask_buf, sizeof(netmask_buf));
                }

                if (ifa->ifa_flags & IFF_BROADCAST && ifa->ifa_broadaddr) {
                    auto broad = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_broadaddr);
                    inet_ntop(AF_INET, &(broad->sin_addr), broadcast_buf, sizeof(broadcast_buf));
                }

                if (ifa->ifa_flags & IFF_POINTOPOINT && ifa->ifa_dstaddr) {
                    auto peer = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_dstaddr);
                    inet_ntop(AF_INET, &(peer->sin_addr), peer_buf, sizeof(peer_buf));
                }

                local_ip_address_v4 addr{
                    std::string(addr_buf),
                    std::string(netmask_buf),
                    std::string(broadcast_buf),
                    std::string(peer_buf),
                    (ifa->ifa_flags & IFF_LOOPBACK) != 0,
                    (ifa->ifa_flags & IFF_MULTICAST) != 0
                };

                iface.ipv4.emplace_back(std::move(addr));
            } else if (ifa->ifa_addr->sa_family == AF_INET6) {
                auto sa6 = reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_addr);
                if (!inet_ntop(AF_INET6, &(sa6->sin6_addr), addr_buf, sizeof(addr_buf)))
                    continue;

                if (ifa->ifa_netmask) {
                    auto netmask6 = reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_netmask);
                    inet_ntop(AF_INET6, &(netmask6->sin6_addr), netmask_buf, sizeof(netmask_buf));
                }

                std::string scope_id_str;
                if (sa6->sin6_scope_id != 0) {
                    scope_id_str = std::to_string(sa6->sin6_scope_id);
                }

                local_ip_address_v6 addr6{
                    std::string(addr_buf),
                    std::string(netmask_buf),
                    (ifa->ifa_flags & IFF_LOOPBACK) != 0,
                    (ifa->ifa_flags & IFF_MULTICAST) != 0,
                    IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr),
                    std::move(scope_id_str)
                };

                iface.ipv6.emplace_back(std::move(addr6));
            }
        }

        freeifaddrs(ifaddr);

        list.reserve(iface_map.size());
        for (auto& snd: iface_map | std::views::values) {
            list.emplace_back(std::move(snd));
        }

        return list;
    }
#endif
#ifdef SSOCK_WINDOWS
    inline std::vector<network_interface> get_interfaces() {
        std::vector<network_interface> list;
        ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
        ULONG family = AF_UNSPEC;

        ULONG out_buf_len = 15000;
        std::vector<char> buffer(out_buf_len);

        auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

        if (GetAdaptersAddresses(family, flags, nullptr, adapters, &out_buf_len) == ERROR_BUFFER_OVERFLOW) {
            buffer.resize(out_buf_len);
            adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        }

        DWORD ret = GetAdaptersAddresses(family, flags, nullptr, adapters, &out_buf_len);
        if (ret != NO_ERROR) {
            throw std::runtime_error("GetAdaptersAddresses() failed in get_interfaces()");
        }

        for (IP_ADAPTER_ADDRESSES* adapter = adapters; adapter != nullptr; adapter = adapter->Next) {
            network_interface iface;
            iface.name = adapter->AdapterName;

            iface.up = (adapter->OperStatus == IfOperStatusUp);
            iface.running = iface.up;
            iface.broadcast = true;
            iface.point_to_point = false;

            for (IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress; unicast != nullptr; unicast = unicast->Next) {
                SOCKADDR* addr = unicast->Address.lpSockaddr;
                char addr_str[INET6_ADDRSTRLEN] = {};
                char netmask_str[INET6_ADDRSTRLEN] = {};

                if (addr->sa_family == AF_INET) {
                    auto sa = reinterpret_cast<sockaddr_in*>(addr);
                    inet_ntop(AF_INET, &sa->sin_addr, addr_str, sizeof(addr_str));

                    ULONG mask = (unicast->OnLinkPrefixLength == 0) ? 0 : 0xFFFFFFFF << (32 - unicast->OnLinkPrefixLength);
                    in_addr netmask{};
                    netmask.S_un.S_addr = htonl(mask);
                    inet_ntop(AF_INET, &netmask, netmask_str, sizeof(netmask_str));

                    iface.ipv4.emplace_back(
                        std::string(addr_str),
                        std::string(netmask_str),
                        "",
                        "",
                        (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK),
                        true
                    );

                } else if (addr->sa_family == AF_INET6) {
                    auto sa6 = reinterpret_cast<sockaddr_in6*>(addr);
                    inet_ntop(AF_INET6, &sa6->sin6_addr, addr_str, sizeof(addr_str));

                    iface.ipv6.emplace_back(
                        std::string(addr_str),
                        "",
                        (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK),
                        true,
                        static_cast<bool>(IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr)),
                        std::to_string(sa6->sin6_scope_id)
                    );
                }
            }

            list.emplace_back(std::move(iface));
        }

        return list;
    }
#endif
    /**
     * @brief Check if there is a usable IPv4 address on the system.
     * @return True if a usable IPv4 address exists, false otherwise.
     */
    static bool usable_ipv6_address_exists() {
        static auto interfaces = get_interfaces();

        for (const auto& iface : interfaces) {
            if (!iface.is_up()) continue;

            for (const auto& addr : iface.get_ipv6_addrs()) {
                const auto& ip = addr.get_ip();
                if (ip.empty()) continue;

                if (addr.is_loopback() || addr.is_link_local() || addr.is_multicast()) {
                    continue;
                }

                return true;
            }
        }

        return false;
    }
    /**
     * @brief Check if a string is a valid IPv4 address.
     * @param ip The string to check.
     * @return True if the string is a valid IPv4 address, false otherwise.
     */
    static bool is_ipv4(const std::string& ip) {
        sockaddr_in sa{};
        return inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) != 0;
    }
    /**
     * @brief Check if a string is a valid IPv6 address.
     * @param ip The string to check.
     * @return True if the string is a valid IPv6 address, false otherwise.
     */
    static bool is_ipv6(const std::string& ip) {
        sockaddr_in6 sa{};
        return inet_pton(AF_INET6, ip.c_str(), &(sa.sin6_addr)) != 0;
    }
    /**
     * @brief Check if a port is valid.
     * @param port The port to check.
     * @return True if the port is valid, false otherwise.
     */
    static bool is_valid_port(const int port) {
        return port > 0 && port <= 65535;
    }
}


namespace ssock::internal_net {
    ssock::network::sock_ip_list get_a_aaaa_from_hostname(const std::string& hostname);
}

/**
 * @brief Namespace for the ssock library.
 */
namespace ssock::sock {
    class sync_sock;
    class sock_addr;

    /**
     * @brief Socket file descriptor type.
     * @note This is a typedef for int, but can be changed to a different type if needed.
     */
#ifdef SSOCK_WINDOWS
    using sock_fd_t = SOCKET;
#elifdef SSOCK_UNIX
    using sock_fd_t = int;
#endif
    using sock_addr_type = network::sock_addr_type;

    /**
     * @brief Socket types.
     */
    enum class sock_type {
        tcp, /* TCP socket */
        udp, /* UDP socket */
        unix, /* UNIX domain socket */
    };
    /**
     * @brief Socket options.
     * @note These options can be used with the sync_sock class to set socket options.
     */
    enum class sock_opt {
        reuse_addr = 1 << 0, /* Reuse address option */
        no_reuse_addr = 1 << 1, /* Do not reuse address option */
        no_delay = 1 << 2, /* Disable Nagle's algorithm (TCP_NODELAY) */
        keep_alive = 1 << 3, /* Enable keep-alive option */
        no_keep_alive = 1 << 4, /* Disable keep-alive option */
        no_blocking = 1 << 5, /* Set socket to non-blocking mode. Not necessarily supported. */
        blocking = 1 << 6, /* Set socket to blocking mode */
    };

    /**
     * @brief Socket receive status.
     * @note This enum is used to indicate the status of a socket receive operation.
     */
    enum class sock_recv_status {
        success,
        timeout,
        closed,
        error
    };

    /**
     * @brief Result of a socket receive operation.
     * @note This struct contains the result data and the status of the receive operation.
     */
    struct sock_recv_result {
        std::string data{};
        sock_recv_status status{sock_recv_status::success};
    };

    inline sock_opt operator|(sock_opt lhs, sock_opt rhs) {
        using T = std::underlying_type_t<sock_opt>;
        return static_cast<sock_opt>(static_cast<T>(lhs) | static_cast<T>(rhs));
    }

    inline bool operator&(sock_opt lhs, sock_opt rhs) {
        using T = std::underlying_type_t<sock_opt>;
        return static_cast<T>(lhs) & static_cast<T>(rhs);
    }

    using sock_ip_list = network::sock_ip_list;

    /**
     * @brief Get the peer address of a socket.
     * @param sockfd The socket file descriptor.
     * @return A sock_addr object that contains the peer address of the socket.
     */
    static sock_addr get_peer(sock_fd_t sockfd);
    /**
     * @brief A class that represents a socket address.
     * @param hostname The hostname or IP address to resolve.
     * @param port The port to use.
     * @param t The address type (ipv4, ipv6, hostname_ipv4, hostname_ipv6).
     */
    class sock_addr final {
        std::filesystem::path path{};
        std::string hostname{};
        std::string ip{};
        int port{};
        sock_addr_type type{sock_addr_type::hostname};
        friend sock_addr get_peer(sock_fd_t);

        sock_addr() = default;
    public:
        /**
         * @brief Constructs a sock_addr object.
         * @param hostname The hostname or IP address to resolve.
         * @param port The port to use.
         * @param t The address type (ipv4, ipv6, hostname_ipv4, hostname_ipv6).
         */
        sock_addr(const std::string& hostname, int port, sock_addr_type t) : hostname(hostname), port(port), type(t) {
            const auto resolve_host = [](const std::string& h, bool t) -> std::string {
                try {
                    auto ip_list = internal_net::get_a_aaaa_from_hostname(h);
                    auto ip = t ? ip_list.get_ipv6() : ip_list.get_ipv4();
                    return ip;
                } catch (const std::exception&) {
                    return {};
                }
            };

            if (type == sock_addr_type::hostname) {
                ip = resolve_host(hostname, true);
                type = ssock::sock::sock_addr_type::ipv6;

                if (!ssock::network::usable_ipv6_address_exists()) {
                    ip.clear();
                }

                if (ip.empty()) {
                    ip = resolve_host(hostname, false);
                    type = ssock::sock::sock_addr_type::ipv4;
                }
            } else if (type == sock_addr_type::hostname_ipv4) {
                ip = resolve_host(hostname, false);
                type = ssock::sock::sock_addr_type::ipv4;
            } else if (type == sock_addr_type::hostname_ipv6) {
                ip = resolve_host(hostname, true);
                type = ssock::sock::sock_addr_type::ipv6;
            } else if (type == sock_addr_type::ipv4 || type == sock_addr_type::ipv6) {
                ip = hostname;
            } else {
                throw ip_error("sock_addr(): invalid address type");
            }

            if (ip.empty()) {
                throw ip_error("sock_addr(): could not resolve hostname or invalid IP address");
            }

            if (!network::is_ipv4(ip) && !network::is_ipv6(ip)) {
                throw parsing_error("sock_addr(): invalid address type (constructor)");
            }

            if (this->hostname == ip) {
                this->hostname.clear();
            }
        }
        /**
         * @brief Constructs a sock_addr object for a file path.
         * @param path The file path to use.
         * @throws parsing_error if the path does not exist.
         */
        explicit sock_addr(const std::filesystem::path& path) : path(path), type(sock_addr_type::filename) {
            if (!std::filesystem::exists(path)) {
                throw parsing_error("sock_addr(): path does not exist");
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
         * @brief Check whether the address is a file path.
         * @return True if the address is a file path, false if it is an IP address, hostname or invalid.
         */
        [[nodiscard]] bool is_file_path() const noexcept {
            return type == sock_addr_type::filename;
        }
        /**
         * @brief Get the stored IP address.
         * @return The stored IP address.
         */
        [[nodiscard]] std::string get_ip() const {
            if (type == sock_addr_type::filename) {
                throw parsing_error("sock_addr(): cannot get IP from a file path");
            }

            return this->ip;
        }
        /**
         * @brief Get the stored file path.
         * @return The stored file path.
         */
        [[nodiscard]] std::filesystem::path get_path() const {
            if (type != sock_addr_type::filename) {
                throw parsing_error("sock_addr(): cannot get path from an IP address or hostname");
            }
            return this->path;
        }
        /**
         * @brief Get the stored hostname.
         * @return The stored hostname.
         */
        [[nodiscard]] std::string get_hostname() const {
            if (hostname.empty()) {
                throw parsing_error("hostname is empty, use get_ip() instead");
            }
            if (type == sock_addr_type::filename) {
                throw parsing_error("sock_addr(): cannot get hostname from a file path");
            }
            return hostname;
        }
        /**
         * @brief Get the stored port.
         * @return The stored port.
         */
        [[nodiscard]] int get_port() const {
            if (type == sock_addr_type::filename) {
                throw parsing_error("sock_addr(): cannot get port from a file path");
            }

            return port;
        }
        ~sock_addr() = default;
    };

    /**
     * @brief A class that represents a synchronous socket.
     * @note This class is an abstract base class and should not be instantiated directly.
     * @note Use the sync_sock class instead.
     */
    class basic_sync_sock {
      public:
        virtual ~basic_sync_sock() = default;

        virtual void connect() = 0;
        virtual void bind() = 0;
        virtual void unbind() = 0;
        virtual void listen(int backlog) = 0;
        virtual void listen() = 0;
        virtual std::unique_ptr<sync_sock> accept() = 0;
        virtual int send(const void* buf, size_t len) = 0;
        virtual void send(const std::string& buf) = 0;
        [[nodiscard]] virtual sock_recv_result recv(int timeout_seconds) const = 0;
        [[nodiscard]] virtual sock_recv_result recv(int timeout_seconds, const std::string& match) const = 0;
        [[nodiscard]] virtual sock_recv_result recv(int timeout_seconds, const std::string& match, size_t eof) const = 0;
        [[nodiscard]] virtual sock_recv_result recv(int timeout_seconds, size_t eof) const = 0;
        [[nodiscard]] virtual std::string overflow_bytes() const = 0;
        virtual void clear_overflow_bytes() const = 0;
        virtual void close() = 0;
    };

    /**
     * @brief A class that represents a synchronous socket.
     */
    class sync_sock : basic_sync_sock {
        sock_addr addr;
        sock_type type{};
#ifdef SSOCK_WINDOWS
        sock_fd_t sockfd{INVALID_SOCKET};
#else
        sock_fd_t sockfd{-1};
#endif
        sockaddr_storage sa_storage{};
        bool bound{false};
        mutable std::string old_bytes;

        [[nodiscard]] const sockaddr* get_sa() const {
            return reinterpret_cast<const sockaddr*>(&sa_storage);
        }

        [[nodiscard]] socklen_t get_sa_len() const {
            if (addr.is_ipv4()) return sizeof(sockaddr_in);
            if (addr.is_ipv6()) return sizeof(sockaddr_in6);
            if (addr.is_file_path()) {
                const auto& path = addr.get_path();
                return static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + path.string().size() + 1);
            }

            throw socket_error("invalid address type");
        }

        void prep_sa() {
            memset(&sa_storage, 0, sizeof(sa_storage));
            if (addr.is_ipv4()) {
                auto* sa4 = reinterpret_cast<sockaddr_in*>(&sa_storage);
                sa4->sin_family = AF_INET;
                sa4->sin_port = htons(addr.get_port());
                if (inet_pton(AF_INET, addr.get_ip().c_str(), &sa4->sin_addr) <= 0) {
                    throw parsing_error("invalid IPv4 address");
                }
            } else if (addr.is_ipv6()) {
                auto* sa6 = reinterpret_cast<sockaddr_in6*>(&sa_storage);
                sa6->sin6_family = AF_INET6;
                sa6->sin6_port = htons(addr.get_port());
                if (inet_pton(AF_INET6, addr.get_ip().c_str(), &sa6->sin6_addr) <= 0) {
                    throw parsing_error("invalid IPv6 address");
                }
            } else if (addr.is_file_path()) {
                auto* sa_un = reinterpret_cast<sockaddr_un*>(&sa_storage);
                sa_un->sun_family = AF_UNIX;
                const auto& path = addr.get_path().string();
                if (path.size() >= sizeof(sa_un->sun_path)) {
                    throw socket_error("UNIX socket path too long");
                }
                std::memcpy(sa_un->sun_path, path.c_str(), path.size() + 1);
            } else {
                throw ip_error("invalid address type");
            }
        }

#ifdef SSOCK_UNIX
        void set_sock_opts(sock_opt opts) const {
            if (opts & sock_opt::reuse_addr) {
                internal_net::sys_net_setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opts, sizeof(opts));
            } else if (opts & sock_opt::no_reuse_addr) {
                internal_net::sys_net_setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, nullptr, 0);
            }
            if (opts & sock_opt::no_delay) {
                internal_net::sys_net_setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &opts, sizeof(opts));
            }
            if (opts & sock_opt::keep_alive) {
                internal_net::sys_net_setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &opts, sizeof(opts));
            } else if (opts & sock_opt::no_keep_alive) {
                internal_net::sys_net_setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, nullptr, 0);
            }
            if (opts & sock_opt::no_blocking) {
                int flags = fcntl(this->sockfd, F_GETFL, 0);
                if (flags < 0) {
                    internal_net::sys_net_close(this->sockfd);
                    throw socket_error("failed to get socket flags");
                }
                if (fcntl(this->sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
                    internal_net::sys_net_close(this->sockfd);
                    throw socket_error("failed to set socket to non-blocking mode");
                }
            } else if (opts & sock_opt::blocking) {
                int flags = fcntl(this->sockfd, F_GETFL, 0);
                if (flags < 0) {
                    internal_net::sys_net_close(this->sockfd);
                    throw socket_error("failed to get socket flags");
                }
                if (fcntl(this->sockfd, F_SETFL, flags & ~O_NONBLOCK) < 0) {
                    internal_net::sys_net_close(this->sockfd);
                    throw socket_error("failed to set socket to blocking mode");
                }
            }
        }
#endif
#ifdef SSOCK_WINDOWS
        void set_sock_opts(sock_opt opts) {
            if (opts & sock_opt::reuse_addr) {
                BOOL optval = TRUE;
                if (setsockopt(this->sockfd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&optval), sizeof(optval)) == SOCKET_ERROR) {
                    closesocket(this->sockfd);
                    throw socket_error("failed to set SO_REUSEADDR");
                }
            } else if (opts & sock_opt::no_reuse_addr) {
                BOOL optval = FALSE;
                if (setsockopt(this->sockfd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&optval), sizeof(optval)) == SOCKET_ERROR) {
                    closesocket(this->sockfd);
                    throw socket_error("failed to clear SO_REUSEADDR");
                }
            }
            if (opts & sock_opt::no_delay) {
                BOOL optval = TRUE;
                if (setsockopt(this->sockfd, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&optval), sizeof(optval)) == SOCKET_ERROR) {
                    closesocket(this->sockfd);
                    throw socket_error("failed to set TCP_NODELAY");
                }
            }
            if (opts & sock_opt::keep_alive) {
                BOOL optval = TRUE;
                if (setsockopt(this->sockfd, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char*>(&optval), sizeof(optval)) == SOCKET_ERROR) {
                    closesocket(this->sockfd);
                    throw socket_error("failed to set SO_KEEPALIVE");
                }
            } else if (opts & sock_opt::no_keep_alive) {
                BOOL optval = FALSE;
                if (setsockopt(this->sockfd, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char*>(&optval), sizeof(optval)) == SOCKET_ERROR) {
                    closesocket(this->sockfd);
                    throw socket_error("failed to clear SO_KEEPALIVE");
                }
            }
            if (opts & sock_opt::no_blocking) {
                u_long mode = 1;
                if (ioctlsocket(this->sockfd, FIONBIO, &mode) == SOCKET_ERROR) {
                    closesocket(this->sockfd);
                    throw socket_error("failed to set socket to non-blocking mode");
                }
            } else if (opts & sock_opt::blocking) {
                u_long mode = 0;
                if (ioctlsocket(this->sockfd, FIONBIO, &mode) == SOCKET_ERROR) {
                    closesocket(this->sockfd);
                    throw socket_error("failed to set socket to blocking mode");
                }
            }
        }
#endif
    public:
        /**
         * @brief Constructs a sync_sock object.
         * @param addr The socket address to bind to.
         * @param t The socket type (tcp, udp, unix).
         * @param opts The socket options (reuse_addr, no_reuse_addr).
         */
#ifdef SSOCK_UNIX
        sync_sock(const sock_addr& addr, sock_type t, sock_opt opts = sock_opt::no_reuse_addr|sock_opt::no_delay|sock_opt::blocking) : addr(addr), type(t) {
            this->sockfd = -1;

            if (addr.get_ip().empty() && !addr.is_file_path()) {
                throw socket_error("IP address/file path is empty");
            }

            if (t != sock_type::unix) {
                this->sockfd = internal_net::sys_net_socket(addr.is_ipv6() ? AF_INET6 : AF_INET,
                                                                  t == sock_type::tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
            } else {
                this->sockfd = internal_net::sys_net_socket(AF_UNIX, SOCK_STREAM, 0);
            }

            if (this->sockfd < 0) {
                throw socket_error("failed to create socket");
            }

            if (this->sockfd >= 0) {
                this->set_sock_opts(opts);
            } else {
                throw socket_error("cannot set options on invalid socket");
            }

            this->prep_sa();
        }
        /**
         * @brief Constructs a sync_sock object from an existing file descriptor.
         * @param existing_fd The existing file descriptor.
         * @param peer The peer address of the socket.
         * @param t The socket type (tcp, udp, unix).
         * @param opts The socket options (reuse_addr, no_reuse_addr).
         */
        sync_sock(int existing_fd, const sock_addr& peer, sock_type t, sock_opt opts = sock_opt::no_reuse_addr|sock_opt::no_delay|sock_opt::blocking)
            : sockfd(existing_fd), addr(peer), type(t) {
            if (sockfd < 0) throw socket_error("invalid fd");
            if (this->sockfd >= 0) {
                this->set_sock_opts(opts);
            } else {
                throw socket_error("cannot set options on invalid socket");
            }

            this->prep_sa();
        }
#endif
#ifdef SSOCK_WINDOWS
        sync_sock(const sock_addr& addr, sock_type t, sock_opt opts = sock_opt::no_reuse_addr|sock_opt::no_delay|sock_opt::blocking)
            : addr(addr), type(t) {

            if (addr.get_ip().empty() && !addr.is_file_path()) {
                throw socket_error("IP address or file path is empty");
            }

            int domain = AF_UNIX;
            int sock_type = SOCK_STREAM;
            int protocol = 0;

            if (t != sock_type::unix) {
                domain = addr.is_ipv6() ? AF_INET6 : AF_INET;
                sock_type = (t == sock_type::tcp) ? SOCK_STREAM : SOCK_DGRAM;
                protocol = (t == sock_type::tcp) ? IPPROTO_TCP : IPPROTO_UDP;
            } else {
                protocol = 0;
            }

            this->sockfd = socket(domain, sock_type, protocol);
            if (this->sockfd == INVALID_SOCKET) {
                throw socket_error("Failed to create socket");
            }

            this->set_sock_opts(opts);
            this->prep_sa();
        }
#endif
#ifdef SSOCK_UNIX
        ~sync_sock() override {
            if (this->sockfd == -1) {
                return;
            }
            if (internal_net::sys_net_close(this->sockfd) < 0) {
                ;
            }
        }
#endif
#ifdef SSOCK_WINDOWS
        ~sync_sock() override {
            if (this->sockfd == INVALID_SOCKET) {
                return;
            }

            if (::closesocket(this->sockfd) == SOCKET_ERROR) {
                return;
            }

            this->sockfd = INVALID_SOCKET;
        }
#endif
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
#ifdef SSOCK_UNIX
        void connect() override {
            if (internal_net::sys_net_connect(this->sockfd, this->get_sa(), this->get_sa_len()) < 0) {
                throw socket_error("failed to connect to server");
            }
        }
#endif
#ifdef SSOCK_WINDOWS
        void connect() override {
            if (::connect(this->sockfd, this->get_sa(), this->get_sa_len()) == SOCKET_ERROR) {
                throw socket_error("failed to connect to server");
            }
        }
#endif
        /**
         * @brief Bind the socket to the address.
         */
#ifdef SSOCK_UNIX
        void bind() override {
            this->bound = true;

            auto ret = internal_net::sys_net_bind(this->sockfd, this->get_sa(), this->get_sa_len());

            if (ret < 0) {
                throw socket_error("failed to bind socket: " + std::to_string(ret));
            }
        }
#endif
#ifdef SSOCK_WINDOWS
        void bind() override {
            this->bound = true;

            int result = ::bind(this->sockfd, this->get_sa(), this->get_sa_len());

            if (result == SOCKET_ERROR) {
                int err = WSAGetLastError();
                throw socket_error("failed to bind socket, error code: " + std::to_string(err));
            }
        }
#endif
        /**
         * @brief Unbind the socket from the address.
         */
#ifdef SSOCK_UNIX
        void unbind() override {
            if (this->bound) {
                if (internal_net::sys_net_close(this->sockfd) < 0) {
                    throw socket_error("failed to unbind socket");
                }
                this->bound = false;
            }
        }
#endif
#ifdef SSOCK_WINDOWS
        void unbind() override {
            if (this->bound) {
                if (::closesocket(this->sockfd) == SOCKET_ERROR) {
                    int err = WSAGetLastError();
                    throw socket_error("failed to close socket, error code: " + std::to_string(err));
                }
                this->bound = false;
                this->sockfd = INVALID_SOCKET;
            }
        }
#endif
        /**
         * @brief Listen for incoming connections.
         * @param backlog The maximum number of pending connections.
         * @note Very barebones, use with care.
         */
#ifdef SSOCK_UNIX
        void listen(int backlog) override {
            if (internal_net::sys_net_listen(this->sockfd, backlog == -1 ? SOMAXCONN : backlog) < 0) {
                throw socket_error("failed to listen on socket");
            }
        }
#endif
#ifdef SSOCK_WINDOWS
        void listen(int backlog) override {
            if (::listen(this->sockfd, backlog == -1 ? SOMAXCONN : backlog) == SOCKET_ERROR) {
                int err = WSAGetLastError();
                throw socket_error("failed to listen socket, error code: " + std::to_string(err));
            }
        }
#endif
        /**
         * @brief Listen for incoming connections with default backlog.
         * @note Uses SOMAXCONN as the default backlog value.
         */
        void listen() override {
            listen(-1);
        }
        /**
         * @brief Accept a connection from a client.
         * @return sock_handle The socket handle for the accepted connection.
         */
#ifdef SSOCK_UNIX
        [[nodiscard]] std::unique_ptr<sync_sock> accept() override {
            sockaddr_storage client_addr{};
            socklen_t addr_len = sizeof(client_addr);

            int client_sockfd = internal_net::sys_net_accept(this->sockfd,
                                                             reinterpret_cast<sockaddr*>(&client_addr),
                                                             &addr_len);
            if (client_sockfd < 0) {
                throw socket_error("failed to accept connection: " + std::string(strerror(errno)));
            }

            auto peer = sock::get_peer(client_sockfd);

            return std::make_unique<sync_sock>(client_sockfd, peer, this->type);
        }
#endif
#ifdef SSOCK_WINDOWS
        [[nodiscard]] std::unique_ptr<sync_sock> accept() override {
            sockaddr_storage client_addr{};
            int addr_len = sizeof(client_addr);

            SOCKET client_sockfd = ::accept(this->sockfd, reinterpret_cast<sockaddr*>(&client_addr), &addr_len);
            if (client_sockfd == INVALID_SOCKET) {
                int err = WSAGetLastError();
                throw socket_error("failed to accept connection, error code: " + std::to_string(err));
            }

            auto peer = sock::get_peer(client_sockfd);
            auto handle = std::make_unique<sync_sock>(peer, this->type);
            handle->sockfd = client_sockfd;

            return handle;
        }
#endif
        /**
         * @brief Send data to the server.
         * @param buf The data to send.
         * @param len The length of the data.
         * @return The number of bytes sent.
         */
#ifdef SSOCK_UNIX
        int send(const void* buf, size_t len) override {
            size_t total_sent = 0;
            const char* data = static_cast<const char*>(buf);

            while (total_sent < len) {
                ssize_t sent = internal_net::sys_net_send(this->sockfd, data + total_sent, len - total_sent, 0);
                if (sent <= 0) {
                    return static_cast<int>(sent);
                }
                total_sent += sent;
            }

            return static_cast<int>(total_sent);
        }
#endif
#ifdef SSOCK_WINDOWS
        int send(const void* buf, size_t len) override {
            size_t total_sent = 0;
            const char* data = static_cast<const char*>(buf);

            while (total_sent < len) {
                int ret = ::send(this->sockfd, data + total_sent, static_cast<int>(len - total_sent), 0);
                if (ret == SOCKET_ERROR) {
                    int err = WSAGetLastError();
                    throw socket_error("send() failed, error code: " + std::to_string(err));
                }
                if (ret == 0) {
                    break;
                }
                total_sent += ret;
            }

            return static_cast<int>(total_sent);
        }
#endif
        /**
         * @brief Send a string to the server.
         * @param buf The string to send.
         */
        void send(const std::string& buf) override {
            static_cast<void>(this->send(buf.c_str(), buf.length()));
        }

        /**
         * @brief Returns bytes that were read, further than the requested length (as defined by the eof parameter in recv()).
         * @note This does NOT need to be called if you intend to call recv() again, as recv() prepends these bytes automatically.
         * @note Call clear_overflow_bytes() after calling, if you do not want recv() to use these bytes again.
         * @return std::string of overflow bytes.
         */
        [[nodiscard]] std::string overflow_bytes() const override {
            return old_bytes;
        }
        /**
         * @brief Clear the overflow bytes buffer.
         * @note This does NOT need to be called if you intend to call recv() again, as recv() prepends these bytes automatically.
         */
        void clear_overflow_bytes() const override {
            old_bytes.clear();
        }
        /**
         * @brief Receive data from the server.
         * @param timeout_seconds The timeout in seconds (-1 means wait indefinitely until match is found)
         * @param match The substring to look for in received data.
         * @param eof The number of bytes to read before considering the match complete.
         * @return The received data as a sock_recv_result object.
         */
#ifdef SSOCK_UNIX
        [[nodiscard]] sock_recv_result recv(const int timeout_seconds, const std::string& match, size_t eof) const override {
            std::string data = old_bytes;
            old_bytes.clear();

            if (eof != 0 && data.size() >= eof) {
                if (data.size() > eof) {
                    old_bytes = data.substr(eof);
                    data.resize(eof);
                }
                return {data, sock_recv_status::success};
            }

            if (!match.empty()) {
                size_t pos = data.find(match);
                if (pos != std::string::npos) {
                    old_bytes = data.substr(pos + match.size());
                    data.resize(pos + match.size());
                    return {data, sock_recv_status::success};
                }
            }

            auto start = std::chrono::steady_clock::now();

            while (true) {
                auto elapsed = std::chrono::steady_clock::now() - start;
                auto remaining = std::chrono::seconds(timeout_seconds) - elapsed;
                if (remaining <= std::chrono::seconds(0) && timeout_seconds != -1) {
                    return {data, sock_recv_status::timeout};
                }

                timeval tv{};
                tv.tv_sec = std::chrono::duration_cast<std::chrono::seconds>(remaining).count();
                tv.tv_usec = 0;

                fd_set readfds;
                FD_ZERO(&readfds);
                FD_SET(this->sockfd, &readfds);

                if (this->sockfd < 0) throw socket_error("invalid socket descriptor");
                int ret = internal_net::sys_net_select(this->sockfd + 1, &readfds, nullptr, nullptr,
                                                       timeout_seconds == -1 ? nullptr : &tv);
                if (ret < 0) throw socket_error("select() failed");
                if (ret == 0) return {data, sock_recv_status::timeout};

                if (FD_ISSET(this->sockfd, &readfds)) {
                    size_t bytes_to_read = 8192;
                    if (eof != 0 && data.size() + bytes_to_read > eof) {
                        bytes_to_read = eof - data.size();
                    }

                    char buf[8192];
                    ssize_t received = internal_net::sys_net_recv(this->sockfd, buf, bytes_to_read, 0);
                    if (received < 0) {
                        if (errno == EINTR) continue;
                        throw socket_error("recv() failed");
                    }
                    if (received == 0) return {data, sock_recv_status::closed};

                    data.append(buf, static_cast<std::size_t>(received));

                    if (eof != 0 && data.length() > eof) {
                        old_bytes = data.substr(eof);
                        data.resize(eof);
                    }
                    if (eof != 0 && data.length() >= eof) {
                        return {data, sock_recv_status::success};
                    }

                    if (!match.empty()) {
                        size_t pos = data.find(match);
                        if (pos != std::string::npos) {
                            old_bytes = data.substr(pos + match.size());
                            data.resize(pos + match.size());
                            return {data, sock_recv_status::success};
                        }
                    }
                }
            }
        }
#endif
#ifdef SSOCK_WINDOWS
        [[nodiscard]] sock_recv_result recv(const int timeout_seconds, const std::string& match, size_t eof) const override {
            std::string data = old_bytes;
            old_bytes.clear();

            if (eof != 0 && data.size() >= eof) {
                if (data.size() > eof) {
                    old_bytes = data.substr(eof);
                    data.resize(eof);
                }
                return {data, sock_recv_status::success};
            }

            if (!match.empty()) {
                size_t pos = data.find(match);
                if (pos != std::string::npos) {
                    old_bytes = data.substr(pos + match.size());
                    data.resize(pos + match.size());
                    return {data, sock_recv_status::success};
                }
            }

            auto start = std::chrono::steady_clock::now();

            while (true) {
                auto elapsed = std::chrono::steady_clock::now() - start;
                auto remaining = std::chrono::seconds(timeout_seconds) - elapsed;
                if (timeout_seconds == -1) {
                    remaining = std::chrono::hours(24 * 365 * 100);
                }
                if (remaining <= std::chrono::seconds(0) && timeout_seconds != -1) {
                    return {data, sock_recv_status::timeout};
                }

                timeval tv{};
                tv.tv_sec = static_cast<long>(std::chrono::duration_cast<std::chrono::seconds>(remaining).count());
                tv.tv_usec = 0;

                fd_set readfds;
                FD_ZERO(&readfds);
                FD_SET(this->sockfd, &readfds);

                if (this->sockfd < 0) throw socket_error("invalid socket descriptor");

                int ret = ::select(this->sockfd + 1, &readfds, nullptr, nullptr, timeout_seconds == -1 ? nullptr : &tv);
                if (ret == SOCKET_ERROR) {
                    throw socket_error("select() failed");
                }
                if (ret == 0) {
                    return {data, sock_recv_status::timeout};
                }

                if (FD_ISSET(this->sockfd, &readfds)) {
                    size_t bytes_to_read = 8192;
                    if (eof != 0 && data.size() + bytes_to_read > eof) {
                        bytes_to_read = eof - data.size();
                    }

                    char buf[8192];
                    int received = ::recv(this->sockfd, buf, static_cast<int>(bytes_to_read), 0);
                    if (received == SOCKET_ERROR) {
                        int err = WSAGetLastError();
                        if (err == WSAEINTR) continue;
                        throw socket_error("recv() failed");
                    }
                    if (received == 0) {
                        return {data, sock_recv_status::closed};
                    }

                    data.append(buf, static_cast<std::size_t>(received));

                    if (eof != 0 && data.length() > eof) {
                        old_bytes = data.substr(eof);
                        data.resize(eof);
                    }
                    if (eof != 0 && data.length() >= eof) {
                        return {data, sock_recv_status::success};
                    }

                    if (!match.empty()) {
                        size_t pos = data.find(match);
                        if (pos != std::string::npos) {
                            old_bytes = data.substr(pos + match.size());
                            data.resize(pos + match.size());
                            return {data, sock_recv_status::success};
                        }
                    }
                }
            }
        }
#endif

        /* @brief Receive data from the server.
         * @param timeout_seconds The timeout in seconds (-1 means wait indefinitely).
         * @return The received data as a sock_recv_result
         */
        [[nodiscard]] sock_recv_result recv(const int timeout_seconds) const override {
            return recv(timeout_seconds, "", 0);
        }
        /**
         * @brief Receive data from the server until a specific match is found.
         * @param timeout_seconds The timeout in seconds (-1 means wait indefinitely).
         * @param match The substring to look for in received data.
         * @return The received data as a sock_recv_result object.
         */
        [[nodiscard]] sock_recv_result recv(const int timeout_seconds, const std::string& match) const override {
            return this->recv(timeout_seconds, match, 0);
        }
        /**
         * @brief Receive data from the server until a specific match is found or a certain amount of data is received.
         * @param timeout_seconds The timeout in seconds (-1 means wait indefinitely).
         * @param eof The number of bytes to read before considering the match complete.
         * @return The received data as a sock_recv_result object.
         */
        [[nodiscard]] sock_recv_result recv(const int timeout_seconds, size_t eof) const override {
            return this->recv(timeout_seconds, "", eof);
        }

        /**
         * @brief Close the socket.
         */
#ifdef SSOCK_UNIX
        void close() override {
            if (this->sockfd == -1) {
                return;
            }
            if (internal_net::sys_net_close(this->sockfd) < 0) {
                throw socket_error("failed to close socket");
            }
        }
#endif
#ifdef SSOCK_WINDOWS
        void close() override {
            if (this->sockfd == INVALID_SOCKET) {
                return;
            }

            if (::closesocket(this->sockfd) == SOCKET_ERROR) {
                int err = WSAGetLastError();
                throw socket_error("failed to close socket, error code: " + std::to_string(err));
            }

            this->sockfd = INVALID_SOCKET;
        }
#endif
        [[nodiscard]] sock_addr get_peer() const {
            return ssock::sock::get_peer(this->sockfd);
        }
    };
    sock_addr get_peer(sock_fd_t sockfd);
    /**
     * @brief Resolve a hostname to an IP address.
     * @param hostname The hostname to resolve.
     * @param port The port to use (default is 80).
     * @return A sock_ip_list struct that contains the IPv4 and IPv6 addresses of the hostname.
     */
    static sock_ip_list resolve_hostname(const std::string& hostname, const int port) {
        addrinfo hints{}, *res;

        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        int status = getaddrinfo(hostname.c_str(), std::to_string(port).c_str(), &hints, &res);
        if (status != 0) {
            throw dns_error("resolve_hostname(): function getaddrinfo returned: " + std::string(gai_strerror(status)));
        }

        std::string v4{};
        std::string v6{};

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
                throw ip_error("unknown address family");
            }

            inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
            if (p->ai_family == AF_INET) {
                v4 = ipstr;
            } else if (p->ai_family == AF_INET6) {
                v6 = ipstr;
            }
        }

        freeaddrinfo(res);

        if (v4.empty() && v6.empty()) {
            throw ip_error("retrieved no v4 or v6 address");
        }

        return {std::move(v4), std::move(v6)};
    }
    static sock_addr get_peer(sock_fd_t sockfd) {
        sockaddr_storage addr_storage{};
        socklen_t addr_len = sizeof(addr_storage);

        if (getpeername(sockfd, reinterpret_cast<sockaddr*>(&addr_storage), &addr_len) < 0) {
            throw socket_error("getpeername() failed: " + std::string(strerror(errno)));
        }

        char ip_str[INET6_ADDRSTRLEN] = {0};
        uint16_t port = 0;

        if (addr_storage.ss_family == AF_INET) {
            auto* addr_in = reinterpret_cast<sockaddr_in*>(&addr_storage);
            inet_ntop(AF_INET, &(addr_in->sin_addr), ip_str, sizeof(ip_str));
            port = ntohs(addr_in->sin_port);
        } else if (addr_storage.ss_family == AF_INET6) {
            auto* addr_in6 = reinterpret_cast<sockaddr_in6*>(&addr_storage);
            inet_ntop(AF_INET6, &(addr_in6->sin6_addr), ip_str, sizeof(ip_str));
            port = ntohs(addr_in6->sin6_port);
        } else {
            throw ip_error("unsupported address family");
        }

        sock_addr addr{};
        addr.ip = ip_str;
        addr.port = port;
        addr.type = (addr_storage.ss_family == AF_INET) ?
            sock_addr_type::ipv4 : sock_addr_type::ipv6;

        return addr;
    }

    /**
     * @brief Check if a string is a valid IPv4 address.
     * @param ip The string to check.
     * @return True if the string is a valid IPv4 address, false otherwise.
     */
    static bool is_ipv4(const std::string& ip) {
        sockaddr_in sa{};
        return inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) != 0;
    }
    /**
     * @brief Check if a string is a valid IPv6 address.
     * @param ip The string to check.
     * @return True if the string is a valid IPv6 address, false otherwise.
     */
    static bool is_ipv6(const std::string& ip) {
        sockaddr_in6 sa{};
        return inet_pton(AF_INET6, ip.c_str(), &(sa.sin6_addr)) != 0;
    }
    /**
     * @brief Check if a port is valid.
     * @param port The port to check.
     * @return True if the port is valid, false otherwise.
     */
    static bool is_valid_port(const int port) {
        return port > 0 && port <= 65535;
    }
}

namespace ssock::network::dns {
    class dns_nameserver_list {
        std::vector<std::string> ipv4{};
        std::vector<std::string> ipv6{};

        friend dns_nameserver_list get_nameservers();
    public:
        dns_nameserver_list() = default;
        dns_nameserver_list(std::vector<std::string> ipv4, std::vector<std::string> ipv6)
: ipv4(std::move(ipv4)), ipv6(std::move(ipv6)) {
            if (this->ipv4.empty() && this->ipv6.empty()) {
                throw parsing_error("dns_nameserver(): at least one IP address must be provided");
            }
        }
        [[nodiscard]] std::vector<std::string> get_ipv4() const {
            if (!contains_ipv4()) {
                throw parsing_error("dns_nameserver(): no IPv4 addresses available");
            }
            return ipv4;
        }
        [[nodiscard]] std::vector<std::string> get_ipv6() const {
            if (!contains_ipv6()) {
                throw parsing_error("dns_nameserver(): no IPv6 addresses available");
            }
            return ipv6;
        }
        [[nodiscard]] bool contains_ipv4() const noexcept {
            return !ipv4.empty();
        }
        [[nodiscard]] bool contains_ipv6() const noexcept {
            return !ipv6.empty();
        }
    };
#if defined(SSOCK_UNIX) && !defined(SSOCK_MACOS)
    [[nodiscard]] inline dns_nameserver_list get_nameservers() {
        if (!std::filesystem::exists("/etc/resolv.conf")) {
            throw parsing_error("dns_nameserver(): /etc/resolv.conf does not exist");
        }
        std::ifstream file("/etc/resolv.conf");
        if (!file.is_open()) {
            throw parsing_error("failed to open /etc/resolv.conf");
        }

        std::vector<std::string> ipv4_addrs;
        std::vector<std::string> ipv6_addrs;

        std::string line;
        while (std::getline(file, line)) {
            size_t start = line.find_first_not_of(" \t");
            if (start == std::string::npos) continue;
            if (line.compare(start, 10, "nameserver") != 0) continue;

            std::istringstream iss(line.substr(start));
            std::string keyword, ip;
            iss >> keyword >> ip;

            if (!ip.empty() && ip.front() == '[' && ip.back() == ']') {
                ip = ip.substr(1, ip.size() - 2);
            }

            if (ip.empty()) continue;
            if (is_ipv4(ip)) {
                ipv4_addrs.push_back(ip);
            } else if (is_ipv6(ip)) {
                ipv6_addrs.push_back(ip);
            } else {
                continue;
            }
        }

        return {std::move(ipv4_addrs), std::move(ipv6_addrs)};
    }
#endif
#ifdef SSOCK_MACOS
    [[nodiscard]] inline dns_nameserver_list get_nameservers() {
        SCDynamicStoreRef store = SCDynamicStoreCreate(nullptr, CFSTR("DNSReader"), nullptr, nullptr);
        if (!store) {
            throw parsing_error("failed to create SCDynamicStore");
        }

        auto dns_dict = static_cast<CFDictionaryRef>(SCDynamicStoreCopyValue(store, CFSTR("State:/Network/Global/DNS")));
        if (!dns_dict) {
            CFRelease(store);
            throw parsing_error("failed to get DNS configuration");
        }

        auto servers = static_cast<CFArrayRef>(CFDictionaryGetValue(dns_dict, CFSTR("ServerAddresses")));
        dns_nameserver_list result;

        if (servers && CFGetTypeID(servers) == CFArrayGetTypeID()) {
            CFIndex count = CFArrayGetCount(servers);
            for (CFIndex i = 0; i < count; ++i) {
                auto cf_ip = static_cast<CFStringRef>(CFArrayGetValueAtIndex(servers, i));
                char ip_buf[256];
                if (CFStringGetCString(cf_ip, ip_buf, sizeof(ip_buf), kCFStringEncodingUTF8)) {
                    std::string ip(ip_buf);
                    if (is_ipv4(ip)) {
                        result.ipv4.push_back(ip);
                    } else if (is_ipv6(ip)) {
                        result.ipv6.push_back(ip);
                    }
                }
            }
        }

        CFRelease(dns_dict);
        CFRelease(store);
        return result;
    }
#endif
#ifdef SSOCK_WINDOWS
    [[nodiscard]] inline dns_nameserver_list get_nameservers() {
        std::vector<std::string> ipv4_addrs;
        std::vector<std::string> ipv6_addrs;

        ULONG bufsiz = 0;
        DWORD result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &bufsiz);
        if (result != ERROR_BUFFER_OVERFLOW) {
            throw parsing_error("failed to get adapter buffer size");
        }

        std::vector<char> buffer(bufsiz);
        IP_ADAPTER_ADDRESSES* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

        result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, adapters, &bufsiz);
        if (result != NO_ERROR) {
            throw parsing_error("GetAdaptersAddresses failed");
        }

        for (IP_ADAPTER_ADDRESSES* adapter = adapters; adapter != nullptr; adapter = adapter->Next) {
            IP_ADAPTER_DNS_SERVER_ADDRESS* dns = adapter->FirstDnsServerAddress;
            while (dns) {
                char ipstr[INET6_ADDRSTRLEN] = {};
                sockaddr* sa = dns->Address.lpSockaddr;

                if (sa->sa_family == AF_INET) {
                    auto sin = reinterpret_cast<sockaddr_in*>(sa);
                    inet_ntop(AF_INET, &sin->sin_addr, ipstr, sizeof(ipstr));

                    if (!is_ipv4(ipstr)) {
                        dns = dns->Next;
                        continue;
                    }

                    ipv4_addrs.emplace_back(ipstr);
                } else if (sa->sa_family == AF_INET6) {
                    auto sin6 = reinterpret_cast<sockaddr_in6*>(sa);
                    inet_ntop(AF_INET6, &sin6->sin6_addr, ipstr, sizeof(ipstr));

                    if (!is_ipv6(ipstr)) {
                        dns = dns->Next;
                        continue;
                    }

                    ipv6_addrs.emplace_back(ipstr);
                }

                dns = dns->Next;
            }
        }
    }
#endif
    class dns_query_builder {
        std::vector<uint8_t> packet;
        uint16_t id;
        bool recursion{true};

        void encode_name(const std::string& name) {
            size_t start = 0;
            while (true) {
                size_t pos = name.find('.', start);
                if (pos == std::string::npos) pos = name.size();
                size_t len = pos - start;
                packet.push_back(static_cast<uint8_t>(len));
                for (size_t i = 0; i < len; ++i) {
                    packet.push_back(name[start + i]);
                }
                if (pos == name.size()) break;
                start = pos + 1;
            }
            packet.push_back(0);
        }
        void write_uint16_t(uint16_t value) {
            packet.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
            packet.push_back(static_cast<uint8_t>(value & 0xFF));
        }
        void write_uint32_t(uint32_t value) {
            packet.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
            packet.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
        }
    public:
        explicit dns_query_builder(uint16_t _id = 0): id(_id) {
            if (id == 0) {
                static std::random_device rd;
                static std::mt19937 gen(rd());
                std::uniform_int_distribution<uint16_t> dis(1, 0xFFFF);
                this->id = dis(gen);
            }

            packet.resize(12);

            packet[0] = static_cast<uint8_t>((id >> 8) & 0xFF);
            packet[1] = static_cast<uint8_t>(id & 0xFF);

            uint16_t flags = recursion ? 0x0100 : 0x0000;
            packet[2] = static_cast<uint8_t>((flags >> 8) & 0xFF);
            packet[3] = static_cast<uint8_t>(flags & 0xFF);

            for (int i = 4; i < 12; ++i) {
                packet[i] = 0;
            }
        }

        void set_recursion_desired(bool desired) {
            recursion = desired;
            uint16_t flags = recursion ? 0x0100 : 0x0000;
            packet[2] = static_cast<uint8_t>((flags >> 8) & 0xFF);
            packet[3] = static_cast<uint8_t>(flags & 0xFF);
        }
        void add_question(const std::string& name, network::dns::dns_record_type type = network::dns::dns_record_type::A, uint16_t record_class = 1) {
            encode_name(name);
            write_uint16_t(static_cast<uint16_t>(type));
            write_uint16_t(record_class);

            uint16_t qdcount = (packet[4] << 8) | packet[5];
            ++qdcount;

            packet[4] = static_cast<uint8_t>((qdcount >> 8) & 0xFF);
            packet[5] = static_cast<uint8_t>(qdcount & 0xFF);
        }
        const std::vector<uint8_t>& build() {
            return this->packet;
        }
    };

    class dns_response_parser {
        const std::vector<uint8_t>& data;
        size_t offset = 0;

        uint16_t read_uint16() {
            uint16_t val = (data[offset] << 8) | data[offset + 1];
            offset += 2;
            return val;
        }

        uint32_t read_uint32() {
            uint32_t val = (static_cast<uint32_t>(data[offset]) << 24) |
                           (static_cast<uint32_t>(data[offset + 1]) << 16) |
                           (static_cast<uint32_t>(data[offset + 2]) << 8) |
                           (static_cast<uint32_t>(data[offset + 3]));
            offset += 4;
            return val;
        }

        std::string decode_name(size_t pos_override = std::string::npos) {
            std::string name;
            size_t pos = (pos_override == std::string::npos) ? offset : pos_override;
            bool jumped = false;
            size_t jump_offset = 0;

            while (true) {
                uint8_t len = data[pos];
                if ((len & 0xC0) == 0xC0) {
                    uint16_t pointer = ((len & 0x3F) << 8) | data[pos + 1];
                    if (!jumped) jump_offset = pos + 2;
                    pos = pointer;
                    jumped = true;
                    continue;
                }

                if (len == 0) {
                    if (!jumped)
                        offset = pos + 1;
                    else
                        offset = jump_offset;
                    break;
                }

                if (!name.empty()) name += ".";
                name += std::string(reinterpret_cast<const char*>(&data[pos + 1]), len);
                pos += len + 1;
            }

            return name;
        }

    public:
        explicit dns_response_parser(const std::vector<uint8_t>& bytes) : data(bytes) {
            if (data.size() < 12) throw parsing_error("DNS response too short");
        }

        std::vector<network::dns::dns_record> parse() {
            offset = 0;

            read_uint16();
            read_uint16();
            uint16_t qdcount = read_uint16();
            uint16_t ancount = read_uint16();
            read_uint16();
            read_uint16();

            for (int i = 0; i < qdcount; ++i) {
                decode_name();
                read_uint16();
                read_uint16();
            }

            std::vector<network::dns::dns_record> results;

            for (int i = 0; i < ancount; ++i) {
                std::string name = decode_name();
                uint16_t type = read_uint16();
                uint16_t record_class = read_uint16();
                uint32_t ttl = read_uint32();
                uint16_t rdlength = read_uint16();

                if (type == 0) {
                    throw parsing_error("DNS response contains a zero type record");
                }

                if (offset + rdlength > data.size()) {
                    throw parsing_error("rdata length out of bounds");
                }

                network::dns::dns_record rec;
                rec.name = std::move(name);
                rec.record_class = record_class;
                rec.ttl = ttl;

                if (type == 1 && rdlength == 4) { // A
                    char ipbuf[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &data[offset], ipbuf, sizeof(ipbuf));
                    rec.type = network::dns::dns_record_type::A;
                    rec.data = network::dns::a_record_data{{std::string(ipbuf), ""}};
                    offset += rdlength;
                } else if (type == 28 && rdlength == 16) { // AAAA
                    char ipbuf[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &data[offset], ipbuf, sizeof(ipbuf));
                    rec.type = network::dns::dns_record_type::AAAA;
                    rec.data = network::dns::aaaa_record_data{{"", std::string(ipbuf)}};
                    offset += rdlength;
                } else if (type == 5) { // CNAME
                    auto saved_offset = offset;
                    std::string cname_target = decode_name(offset);
                    rec.type = network::dns::dns_record_type::CNAME;
                    rec.data = network::dns::cname_record_data{std::move(cname_target)};
                    offset = saved_offset + rdlength;
                } else if (type == 15) {
                    // MX
                    if (rdlength < 3) throw parsing_error("malformed MX record");

                    uint16_t preference = (data[offset] << 8) | data[offset + 1];
                    auto saved_offset = offset;
                    std::string exchange = decode_name(offset + 2);
                    rec.type = network::dns::dns_record_type::MX;
                    rec.data = network::dns::mx_record_data{preference, std::move(exchange)};
                    offset = saved_offset + rdlength;
                } else if (type == 2) { // NS
                    auto saved_offset = offset;
                    std::string nsdname = decode_name(offset);
                    rec.type = network::dns::dns_record_type::NS;
                    rec.data = network::dns::ns_record_data{std::move(nsdname)};
                    offset = saved_offset + rdlength;
                } else if (type == 16) { // TXT
                    std::vector<std::string> texts;
                    size_t end = offset + rdlength;
                    while (offset < end) {
                        uint8_t txt_len = data[offset++];
                        if (offset + txt_len > end) {
                            throw parsing_error("TXT record string length out of bounds");
                        }
                        texts.emplace_back(reinterpret_cast<const char*>(&data[offset]), txt_len);
                        offset += txt_len;
                    }
                    rec.type = network::dns::dns_record_type::TXT;
                    rec.data = network::dns::txt_record_data{std::move(texts)};
                } else if (type == 33) { // SRV
                    if (rdlength < 6) {
                        throw parsing_error("SRV record too short");
                    }

                    uint16_t priority = read_uint16();
                    uint16_t weight = read_uint16();
                    uint16_t port = read_uint16();

                    std::string target = decode_name();

                    rec.type = network::dns::dns_record_type::SRV;
                    rec.data = network::dns::srv_record_data{priority, weight, port, std::move(target)};
                } else if (type == 12) { // PTR
                    std::string ptr_name = decode_name();
                    rec.type = network::dns::dns_record_type::PTR;
                    rec.data = network::dns::ptr_record_data{std::move(ptr_name)};
                } else if (type == 6) { // SOA
                    std::string mname = decode_name();
                    std::string rname = decode_name();

                    uint32_t serial = read_uint32();
                    uint32_t refresh = read_uint32();
                    uint32_t retry = read_uint32();
                    uint32_t expire = read_uint32();
                    uint32_t minimum = read_uint32();

                    rec.type = network::dns::dns_record_type::SOA;
                    rec.data = network::dns::soa_record_data{
                        std::move(mname),
                        std::move(rname),
                        serial,
                        refresh,
                        retry,
                        expire,
                        minimum
                    };
                } else {
                    rec.type = network::dns::dns_record_type::OTHER;
                    rec.data = network::dns::generic_record_data{
                        type, std::vector<uint8_t>{data.begin() + static_cast<long>(offset), data.begin() + static_cast<long>(offset) + rdlength}
                    };
                    offset += rdlength;
                }

                results.push_back(std::move(rec));
            }

            return results;
        }
    };

    class basic_dns_cache {
    public:
        virtual ~basic_dns_cache() = default;
        [[nodiscard]] virtual std::vector<network::dns::dns_record> lookup(const std::string& hostname) const = 0;
        virtual void store(const std::string& hostname, const std::vector<network::dns::dns_record>& records) = 0;
    };

    class standard_dns_cache : basic_dns_cache {
    public:
        [[nodiscard]] std::vector<network::dns::dns_record> lookup(const std::string& hostname) const override {
            std::ifstream is(utility::get_standard_cache_location(), std::ios::binary);
            if (!is) {
                return {};
            }

            while (is.peek() != EOF) {
                std::string name = utility::read_string(is);

                uint32_t count = 0;
                utility::read(is, count);

                std::vector<network::dns::dns_record> records;
                records.reserve(count);
                for (uint32_t i = 0; i < count; ++i) {
                    records.push_back(network::dns::dns_record::deserialize(is));
                }

                if (name == hostname) {
                    return records;
                }
            }

            return {};
        }
        void store(const std::string& hostname, const std::vector<network::dns::dns_record>& new_records) override {
            std::ifstream is(utility::get_standard_cache_location(), std::ios::binary);
            std::vector<std::pair<std::string, std::vector<ssock::network::dns::dns_record>>> cache;

            if (is) {
                while (is.peek() != EOF) {
                    std::string name = utility::read_string(is);
                    uint32_t count = 0;
                    utility::read(is, count);

                    std::vector<ssock::network::dns::dns_record> records;
                    records.reserve(count);
                    for (uint32_t i = 0; i < count; ++i) {
                        auto rec = ssock::network::dns::dns_record::deserialize(is);

                        const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch()
                        ).count();

                        if (now_ms < rec.created_at + static_cast<int64_t>(rec.ttl) * 1000) {
                            records.push_back(std::move(rec));
                        }
                    }

                    cache.emplace_back(std::move(name), std::move(records));
                }
            }

            auto it = std::ranges::find_if(cache, [&](const auto& pair) {
                return pair.first == hostname;
            });

            std::vector<ssock::network::dns::dns_record> merged = new_records;

            if (it != cache.end()) {
                const auto& existing = it->second;

                for (const auto& rec : existing) {
                    auto dup = std::ranges::find_if(new_records, [&](const auto& r) {
                        return r.name == rec.name &&
                               r.type == rec.type &&
                               r.record_class == rec.record_class &&
                               r.data == rec.data;
                    });

                    if (dup == new_records.end()) {
                        merged.push_back(rec);
                    }
                }

                it->second = std::move(merged);
            } else {
                cache.emplace_back(hostname, merged);
            }

            std::ofstream os(utility::get_standard_cache_location(), std::ios::binary | std::ios::trunc);
            if (!os) {
                throw std::runtime_error("failed to open DNS cache file for writing");
            }

            for (const auto& [name, records] : cache) {
                utility::write_string(os, name);
                utility::write<uint32_t>(os, static_cast<uint32_t>(records.size()));
                for (const auto& rec : records) {
                    rec.serialize(os);
                }
            }
        }
    };

    template <typename T = standard_dns_cache>
    class basic_sync_dns_resolver {
    public:
        [[nodiscard]] virtual std::vector<network::dns::dns_record> query_records(const std::string& hostname, network::dns::dns_record_type type) const = 0;
        virtual ~basic_sync_dns_resolver() = default;
    };

    template <typename T = standard_dns_cache>
    class sync_dns_resolver : basic_sync_dns_resolver<T> {
        dns_nameserver_list list{};

        void throw_if_invalid() const {
            if (list.contains_ipv4() || list.contains_ipv6()) {
                return;
            }
            throw parsing_error("sync_dns_resolver(): at least one IP address must be provided");
        }
    public:
        explicit sync_dns_resolver(dns_nameserver_list list) : list(std::move(list)) {
            throw_if_invalid();
        }
        sync_dns_resolver() : list(get_nameservers()) {
            throw_if_invalid();
        }

        [[nodiscard]] std::vector<network::dns::dns_record> query_records(const std::string& hostname, network::dns::dns_record_type type) const override {
            throw_if_invalid();

            T cache{};
            auto cached_records = cache.lookup(hostname);

            std::vector<network::dns::dns_record> valid_cached_records;
            auto now = std::chrono::system_clock::now();

            for (const auto& record : cached_records) {
                if (record.type != type) continue;

                auto created_time = std::chrono::system_clock::time_point(std::chrono::milliseconds(record.created_at));
                auto expiry_time = created_time + std::chrono::seconds(record.ttl);

                if (expiry_time < now) {
                    continue; // expired
                }

                valid_cached_records.push_back(record);
            }

            if (!valid_cached_records.empty()) {
                return valid_cached_records;
            }

            dns_query_builder query_builder;
            query_builder.add_question(hostname, type);
            std::vector<unsigned char> query = query_builder.build();

            bool successful = false;
            std::vector<network::dns::dns_record> all_records;

            auto try_query_on_server = [&](const std::string& server, ssock::sock::sock_addr_type addr_type) -> bool {
                auto send_and_parse = [&](ssock::sock::sock_type s_type) -> bool {
                    ssock::sock::sock_addr addr{server, 53, addr_type};
                    ssock::sock::sync_sock sock(addr, s_type, ssock::sock::sock_opt::blocking | ssock::sock::sock_opt::no_delay);

                    sock.connect();

                    if (s_type == ssock::sock::sock_type::tcp) {
                        uint16_t len = htons(static_cast<uint16_t>(query.size()));
                        sock.send(reinterpret_cast<const char*>(&len), 2);
                    }

                    sock.send(reinterpret_cast<const char*>(query.data()), query.size());

                    std::string response{};
                    if (s_type == ssock::sock::sock_type::udp) {
                        response = sock.recv(5, 512).data;
                    } else {
                        std::string len_buf;
                        while (len_buf.size() < 2) {
                            std::string chunk = sock.recv(2, 2 - len_buf.size()).data;
                            if (chunk.empty()) {
                                return false;
                            }
                            len_buf += chunk;
                        }

                        uint16_t resp_len = ntohs(*reinterpret_cast<const uint16_t*>(len_buf.data()));

                        response.reserve(resp_len);
                        size_t total_received = 0;
                        while (total_received < resp_len) {
                            size_t to_read = resp_len - total_received;
                            std::string chunk = sock.recv(5, to_read).data;
                            if (chunk.empty()) {
                                return false;
                            }
                            total_received += chunk.size();
                            response += chunk;
                        }
                    }

                    if (response.size() < 12) return false;

                    std::vector<uint8_t> response_bytes(response.begin(), response.end());
                    if (s_type == ssock::sock::sock_type::udp && (response_bytes[2] & 0x02)) {
                        return false;
                    }

                    dns_response_parser parser(response_bytes);
                    auto records = parser.parse();

                    all_records.insert(all_records.end(), records.begin(), records.end());

                    return true;
                };

                try {
                    if (send_and_parse(ssock::sock::sock_type::udp)) {
                        return true;
                    } else {
                        return send_and_parse(ssock::sock::sock_type::tcp);
                    }
                } catch (...) {
                    return false;
                }
            };

            if (usable_ipv6_address_exists() && list.contains_ipv6()) {
                for (const auto& server : list.get_ipv6()) {
                    if (try_query_on_server(server, ssock::sock::sock_addr_type::ipv6)) {
                        successful = true;
                        break;
                    }
                }
            }

            if (!successful && list.contains_ipv4()) {
                for (const auto& server : list.get_ipv4()) {
                    if (try_query_on_server(server, ssock::sock::sock_addr_type::ipv4)) {
                        successful = true;
                        break;
                    }
                }
            }

            if (!successful) {
                throw dns_error("All DNS queries failed.");
            }

            if (all_records.empty()) {
                throw dns_error("No DNS records found for the hostname: " + hostname);
            }

            cache.store(hostname, all_records);

            return all_records;
        }
    };
}

namespace ssock::internal_net {
    [[nodiscard]] inline network::sock_ip_list get_a_aaaa_from_hostname(const std::string& hostname) {
        if (hostname == "localhost") {
            return {SSOCK_LOCALHOST_IPV4, SSOCK_LOCALHOST_IPV6};
        }
        auto nameservers = ssock::network::dns::get_nameservers();
        if (nameservers.contains_ipv4() == false && nameservers.contains_ipv6() == false) {
            nameservers = {
                {SSOCK_FALLBACK_IPV4_DNS_1, SSOCK_FALLBACK_IPV4_DNS_2},
                {SSOCK_FALLBACK_IPV6_DNS_1, SSOCK_FALLBACK_IPV6_DNS_2},
            };
        }

        ssock::network::dns::sync_dns_resolver resolver(nameservers);

        auto records = resolver.query_records(hostname, ssock::network::dns::dns_record_type::A);
        auto records_v6 = resolver.query_records(hostname, ssock::network::dns::dns_record_type::AAAA);

        std::string v4{};
        std::string v6{};

        records.insert(records.end(), records_v6.begin(), records_v6.end());

        for (const auto& rec : records) {
            std::visit([&v4, &v6]<typename T0>(T0&& data) {
                using T = std::decay_t<T0>;
                if constexpr (std::is_same_v<T, ssock::network::dns::a_record_data>) {
                    v4 = data.ip.get_ipv4();
                } else if constexpr (std::is_same_v<T, ssock::network::dns::aaaa_record_data>) {
                    v6 = data.ip.get_ipv6();
                }
            }, rec.data);
        }

        if (v4.empty() && v6.empty()) {
            throw ssock::dns_error("no valid A or AAAA records found for hostname: " + hostname);
        }

        return {v4, v6};
    }
}

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
     * @brief HTTP status codes and their messages.
     * @note This is a list of common HTTP status codes and their messages.
     */
    struct http_status_code {
        int code;
        std::string_view message;
    };

    /**
     * @brief List of HTTP status codes and their messages.
     * @note This is a static array of http_status_code structs.
     */
    static constexpr std::array<http_status_code, 63> http_status_list = {{
        {100, "Continue"},
        {101, "Switching Protocols"},
        {102, "Processing"},
        {103, "Early Hints"},
        {200, "OK"},
        {201, "Created"},
        {202, "Accepted"},
        {203, "Non-Authoritative Information"},
        {204, "No Content"},
        {205, "Reset Content"},
        {206, "Partial Content"},
        {207, "Multi-Status"},
        {208, "Already Reported"},
        {226, "IM Used"},
        {300, "Multiple Choices"},
        {301, "Moved Permanently"},
        {302, "Found"},
        {303, "See Other"},
        {304, "Not Modified"},
        {305, "Use Proxy"},
        {306, "Switch Proxy"},
        {307, "Temporary Redirect"},
        {308, "Permanent Redirect"},
        {400, "Bad Request"},
        {401, "Unauthorized"},
        {402, "Payment Required"},
        {403, "Forbidden"},
        {404, "Not Found"},
        {405, "Method Not Allowed"},
        {406, "Not Acceptable"},
        {407, "Proxy Authentication Required"},
        {408, "Request Timeout"},
        {409, "Conflict"},
        {410, "Gone"},
        {411, "Length Required"},
        {412, "Precondition Failed"},
        {413, "Content Too Large"},
        {414, "URI Too Long"},
        {415, "Unsupported Media Type"},
        {416, "Range Not Satisfiable"},
        {417, "Expectation Failed"},
        {418, "I'm a teapot"},
        {421, "Misdirected Request"},
        {422, "Unprocessable Content"},
        {423, "Locked"},
        {424, "Failed Dependency"},
        {425, "Too Early"},
        {426, "Upgrade Required"},
        {428, "Precondition Required"},
        {429, "Too Many Requests"},
        {431, "Request Header Fields Too Large"},
        {451, "Unavailable For Legal Reasons"},
        {500, "Internal Server Error"},
        {501, "Not Implemented"},
        {502, "Bad Gateway"},
        {503, "Service Unavailable"},
        {504, "Gateway Timeout"},
        {505, "HTTP Version Not Supported"},
        {506, "Variant Also Negotiates"},
        {507, "Insufficient Storage"},
        {508, "Loop Detected"},
        {510, "Not Extended"},
        {511, "Network Authentication Required"}
    }};

    /**
     * @brief Get the HTTP message for a given status code.
     * @param code The HTTP status code.
     * @return An optional string_view containing the message, or std::nullopt if the code is not found.
     */
    constexpr std::optional<std::string_view> get_http_message(int code) {
        for (const auto& status : http_status_list) {
            if (status.code == code)
                return status.message;
        }
        return std::nullopt;
    }

    /**
     * @brief Get the list of HTTP status codes.
     * @return A constant reference to the array of HTTP status codes.
     */
    constexpr const std::array<http_status_code, http_status_list.size()>& get_http_status_codes() {
        return http_status_list;
    }

    /**
     * @brief A struct that represents an HTTP status line.
     * @note Used to parse the status line of an HTTP response.
     */
    struct http_status_line {
        bool is_response{false};
        int status_code{-1};
        std::string method;
        std::string path;
        std::string version;
    };

    /**
     * @brief A struct that represents an HTTP response.
     */
    struct response {
        int status_code{};
        std::string body{};
        http_status_line status_line{};

        std::vector<std::pair<std::string, std::string>> headers{};
    };

    /**
     * @brief Basic HTTP body parser.
     * @note Splits the body into headers and body.
     */
    template <typename T = std::istringstream,
              typename R = response,
              typename VPS = std::vector<std::pair<T,T>>>
    class body_parser {
        const T& input;
        R ret{};
        VPS headers{};
        T body{};
        http_status_line status_line{};
    public:
        /**
         * @brief Constructs a basic_body_parser object.
         * @param input The body to parse.
         */
        explicit body_parser(const T& input) : input(input), ret({}) {
            constexpr auto HEADER_END = "\r\n\r\n";
            const auto pos = input.find(HEADER_END);
            if (pos == std::string::npos) {
                throw parsing_error("no header terminator; invalid HTTP body");
            }

            if (pos + strlen(HEADER_END) < input.length()) {
                this->body = input.substr(pos + strlen(HEADER_END));
            }

            std::string line{};
            std::istringstream hs(input.substr(0, pos));
            while (std::getline(hs, line)) {
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

                    this->headers.emplace_back(key, value);
                }
            }
        }
        ~body_parser() = default;
        /**
         * @brief Parse the status line from the input.
         * @return The parsed http_status_line object.
         */
        http_status_line get_status_line() {
            size_t newline_pos = input.find('\n');
            std::string line = (newline_pos != std::string::npos) ? input.substr(0, newline_pos) : input;

            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }

            if (line.empty()) {
                throw parsing_error("empty HTTP start line");
            }

            std::istringstream iss(line);

            http_status_line msg;

            if (line.compare(0, 5, "HTTP/") == 0) {
                msg.is_response = true;
                iss >> msg.version >> msg.status_code;
                if (iss.fail() || msg.status_code < 100 || msg.status_code > 599) {
                    throw parsing_error("invalid HTTP response status line");
                }
            } else {
                iss >> msg.method >> msg.path >> msg.version;
                if (iss.fail()) {
                    throw parsing_error("invalid HTTP request start line");
                }
                msg.is_response = false;
            }

            return msg;
        }
        /**
         * @brief Get the input stream.
         * @return The input stream (reference)
         */
        [[nodiscard]] T& get_input() {
            return this->input;
        }
        /**
         * @brief Get the body (excluding any headers)
         */
        [[nodiscard]] T& get_body() {
            return this->body;
        }
        /**
         * @brief Get the headers.
         * @return The headers (reference)
         */
        [[nodiscard]] VPS& get_headers() {
            return this->headers;
        }
        /**
         * @brief Parse the body.
         * @return The parsed response (reference)
         */
        [[nodiscard]] R& parse() {
            this->ret = R{};
            this->ret.status_line = get_status_line();
            this->ret.headers = get_headers();
            this->ret.body = get_body();
            this->ret.body = input;

            return ret;
        }
    };

    /**
     * @brief A class that represents an HTTP client.
     */
    class client final {
        std::string hostname{};
        std::string path{};
        int port{};
        method m{};
        version v{};

        std::string method_str{};
        std::string version_str{};
        std::vector<std::pair<std::string,std::string>> headers{};
        std::string body{};
        int timeout{5};

        [[nodiscard]] std::string make_request(const std::string& request) const {
            sock::sock_addr addr(hostname, port, sock::sock_addr_type::hostname_ipv4);
            sock::sync_sock sock(addr, sock::sock_type::tcp);
            sock.connect();
            sock.send(request);

            std::string raw;
            std::string headers;
            while (true) {
                auto result = sock.recv(this->timeout, "\r\n\r\n", 0); // match headers end, no eof limit
                if (result.status == sock::sock_recv_status::timeout) {
                    throw std::runtime_error("timeout while reading headers");
                }
                if (result.status == sock::sock_recv_status::closed) {
                    throw std::runtime_error("connection closed during headers");
                }
                if (result.data.empty()) {
                    throw std::runtime_error("empty recv data unexpectedly");
                }

                raw += result.data;
                if (auto pos = raw.find("\r\n\r\n"); pos != std::string::npos) {
                    headers = raw.substr(0, pos + 4);
                    raw = raw.substr(pos + 4);
                    break;
                }
            }

            bool is_chunked = false;
            std::size_t content_length = 0;

            std::istringstream header_stream(headers);
            std::string line;
            while (std::getline(header_stream, line) && line != "\r") {
                if (line.starts_with("Transfer-Encoding:") && line.find("chunked") != std::string::npos) {
                    is_chunked = true;
                } else if (line.starts_with("Content-Length:")) {
                    content_length = std::stoul(line.substr(15));
                }
            }

            std::string body;

            if (is_chunked) {
                std::string chunked_data = std::move(raw);
                while (chunked_data.find("0\r\n\r\n") == std::string::npos) {
                    std::string chunk = sock.recv(this->timeout, 8192).data;
                    if (chunk.empty()) throw std::runtime_error("connection closed during chunked body");
                    chunked_data += chunk;
                }
                body = utility::decode_chunked(chunked_data);
            } else {
                body = std::move(raw);
                while (body.size() < content_length) {
                    auto res = sock.recv(30, "", 0);
                    if (res.data.empty()) break;
                    body += res.data;
                }
            }

            return headers + body;
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
            if (!sock::is_valid_port(port)) {
                throw parsing_error("invalid port");
            }
            if (hostname.empty()) {
                throw parsing_error("hostname is empty");
            }
            if (path.empty() || path[0] != '/') {
                throw parsing_error("path is empty");
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
                    throw parsing_error("illegal header: " + key);
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
                throw parsing_error("illegal header: " + key);
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
        template <typename BP = body_parser<std::string>>
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

            return BP(ret).parse();
        }
    };

    namespace server {
        /**
         * @brief  Struct that represents a cookie.
         */
        struct cookie {
            std::string name{};
            std::string value{};
            int64_t expires{};
            std::string path{"/"};
            std::string domain{};
            std::string same_site{"Strict"};
            std::vector<std::string> attributes{};
            bool http_only{false};
            bool secure{false};
            std::unordered_map<std::string, std::string> extra_attributes{};
        };

        /**
         * @brief  Struct that represents an HTTP header.
         */
        struct header {
            std::string name{};
            std::string data{};
        };

        enum class redirect_type {
            permanent,
            temporary,
        };

        /**
         * @brief  Struct that contains the server settings.
         */
        struct server_settings {
            int port{8080};
            bool enable_session{true};
            std::string session_directory{"./"};
            std::string session_cookie_name{"session_id"};
            std::vector<std::string> associated_session_cookies{};
            int64_t max_request_size{1024 * 1024 * 1024};
            std::vector<std::string> blacklisted_ips{};
            bool trust_x_forwarded_for{false};
            int max_connections{-1};
            bool session_is_secure{true};
            std::function<std::unordered_map<std::string, std::string>(const std::string&)> read_from_session_file = nullptr;
            std::function<void(const std::string&, const std::unordered_map<std::string, std::string>&)> write_to_session_file = nullptr;
        };

        /**
         * @brief  Struct that contains the request data.
         */
        struct request {
            std::string endpoint{};
            std::unordered_map<std::string, std::string> query{};
            std::string content_type{};
            std::string body{};
            std::string raw_body{};
            std::string method{};
            std::string ip_address{};
            std::string user_agent{};
            unsigned int version{};
            std::vector<cookie> cookies{};
            std::unordered_map<std::string, std::string> session{};
            std::string session_id{};
            std::unordered_map<std::string, std::string> fields{};
        };

        /**
         * @brief  Struct that contains the response data.
         */
        struct response {
            int http_status{200};
            std::string body{};
            std::string content_type{"application/json"};
            std::string allow_origin{"*"};
            bool stop{false};
            std::vector<cookie> cookies{};
            std::vector<std::string> delete_cookies{};
            std::unordered_map<std::string, std::string> session{};
            std::string location{};
            redirect_type redirection{redirect_type::temporary};
            std::vector<header> headers{};
        };

        using request_callback = std::function<response(const request&)>;

        template <typename S = server_settings>
        class basic_request_handler {
        public:
            virtual void handle(std::unique_ptr<sock::sync_sock>&, server_settings&, const request_callback&) const = 0;
            virtual ~basic_request_handler() = default;
        };

        template <typename S = server_settings>
        class request_handler : basic_request_handler<> {
            static std::vector<cookie> get_cookies_from_request(const std::string& cookie_header) {
                std::vector<cookie> cookies;
                std::string cookie_str = cookie_header + ";";

                while (cookie_str.find(';') != std::string::npos) {
                    std::string cookie = cookie_str.substr(0, cookie_str.find(';'));
                    cookie_str = cookie_str.substr(cookie_str.find(';') + 1);

                    std::string name = cookie.substr(0, cookie.find('='));
                    std::string value = cookie.substr(cookie.find('=') + 1);

                    if (!name.empty() && !value.empty()) {
                        if (name.front() == ' ') {
                            name = name.substr(1);
                        }
                        cookies.push_back({name, value});
                    }
                }

                return cookies;
            }

            static std::unordered_map<std::string, std::string> default_read_from_session_file(const std::string& f) {
                std::unordered_map<std::string, std::string> session;

                std::ifstream file(f);

                if (!file.good()) {
                    file.close();
                    return {};
                }

                if (!file.is_open()) {
                    throw std::runtime_error("failed to open session file (read_from_session_file()): " + f);
                }

                std::string line{};
                while (std::getline(file, line)) {
                    if (line.find('=') != std::string::npos) {
                        std::string key = line.substr(0, line.find('='));
                        std::string value = line.substr(line.find('=') + 1);

                        session[key] = value;
                    }
                }

                file.close();

                return session;
            }

            static void default_write_to_session_file(const std::string& f, const std::unordered_map<std::string, std::string>& session) {
                auto directory = std::filesystem::path(f).parent_path();
                if (!std::filesystem::exists(directory)) {
                    std::filesystem::create_directories(directory);
                }
                std::ofstream file(f, std::ios::trunc);

                if (!file.is_open() || !file.good()) {
                    throw std::runtime_error("failed to open session file (write_to_session_file()): " + f);
                }

                for (const auto& it : session) {
                    file << it.first << "=" << it.second << "\n";
                }

                file.close();
            }

            [[nodiscard]] static std::vector<std::pair<std::string, std::string>> get_headers(const std::string& header_part) {
                std::vector<std::pair<std::string,std::string>> headers_vec;
                std::istringstream hs(header_part);
                std::string l{};
                while (std::getline(hs, l) && l != "\r") {
                    if (l.back() == '\r') l.pop_back();
                    auto cpos = l.find(':');
                    if (cpos != std::string::npos) {
                        auto key = l.substr(0, cpos);
                        auto value = l.substr(cpos + 1);
                        auto trim = [](std::string& s) {
                            s.erase(0, s.find_first_not_of(" \t"));
                            s.erase(s.find_last_not_of(" \t") + 1);
                        };
                        trim(key);
                        trim(value);
                        headers_vec.emplace_back(key, value);
                    }
                }

                return headers_vec;
            }

            struct status_line {
                std::string method{"GET"};
                std::string path{"/"};
                std::string http_version{"HTTP/1.1"};
            };

            status_line get_status_line(const std::string& header_part) const {
                status_line line{};
                std::istringstream hs(header_part);
                std::string first_line{};
                if (std::getline(hs, first_line)) {
                    if (first_line.back() == '\r') first_line.pop_back();
                    std::istringstream line_ss(first_line);
                    line_ss >> line.method >> line.path >> line.http_version;
                }
                return line;
            }
        public:
            void handle(std::unique_ptr<sock::sync_sock>& client_sock, server_settings& settings, const request_callback& callback) const override {
                if (!client_sock) {
                    return;
                }

                if (settings.read_from_session_file == nullptr) {
                    settings.read_from_session_file = default_read_from_session_file;
                }
                if (settings.write_to_session_file == nullptr) {
                    settings.write_to_session_file = default_write_to_session_file;
                }

                request req{};
                std::string raw{};
                std::string headers = client_sock->recv(5, "\r\n\r\n").data;
                const auto headers_vec = get_headers(headers);
                if (headers.empty()) {
                    return;
                }
                raw += headers;

                bool is_chunked = false;
                std::size_t content_length = 0;

                auto status_line = get_status_line(headers);
                req.method = status_line.method;

                std::istringstream header_stream(headers);
                std::string line;
                while (std::getline(header_stream, line) && line != "\r") {
                    if (line.starts_with("Transfer-Encoding:") && line.find("chunked") != std::string::npos) {
                        is_chunked = true;
                    } else if (line.starts_with("Content-Length:")) {
                        try {
                            content_length = std::stoul(line.substr(15));
                        } catch (...) {
                            break;
                        }
                    } else if (line.starts_with("Expect:") && line.find("100-continue") != std::string::npos) {
                        client_sock->send("HTTP/1.1 100 Continue\r\n\r\n");
                    } else if (line.starts_with("Expect:") && line.find("100-continue") == std::string::npos) {
                        std::string response = "HTTP/1.1 417 Expectation Failed\r\n"
                            "Content-Length: 0\r\n"
                            "Connection: close\r\n"
                            "\r\n";

                        client_sock->send(response);
                        return;
                    } else if (line.starts_with("Upgrade:") && line.find("websocket") != std::string::npos) {
                        std::string response = "HTTP/1.1 426 Upgrade Required\r\n"
                            "Content-Length: 0\r\n"
                            "Connection: close\r\n"
                            "\r\n";

                        client_sock->send(response);
                        return;
                    } else if (line.starts_with("Connection:") && line.find("close") != std::string::npos) {
                        std::string response = "HTTP/1.1 200 OK\r\n"
                            "Content-Length: 0\r\n"
                            "Connection: close\r\n"
                            "\r\n";

                        client_sock->send(response);
                        return;
                    }
                }

                if (is_chunked && (req.method == "POST" || req.method == "PUT" || req.method == "PATCH" || req.method == "DELETE")) {
                    std::string chunked = client_sock->overflow_bytes();
                    client_sock->clear_overflow_bytes();

                    while (chunked.find("0\r\n\r\n") == std::string::npos) {
                        auto res = client_sock->recv(5, "", 0); // no eof
                        if (res.status == sock::sock_recv_status::closed) break;
                        if (res.status == sock::sock_recv_status::timeout) throw socket_error("recv timeout");
                        if (res.data.empty()) continue;
                        chunked += res.data;
                    }

                    std::string decoded = utility::decode_chunked(chunked);
                    raw = headers + decoded;
                    req.raw_body = raw;
                    req.body = decoded;
                } else if (req.method == "POST" || req.method == "PUT" || req.method == "PATCH" || req.method == "DELETE") {
                    std::string body = client_sock->overflow_bytes();
                    client_sock->clear_overflow_bytes();

                    while (body.size() < content_length) {
                        auto res = client_sock->recv(30, "", 0);
                        if (res.status == sock::sock_recv_status::closed) break;
                        if (res.status == sock::sock_recv_status::timeout) throw socket_error("recv timeout");
                        if (res.data.empty()) continue;
                        body += res.data;
                    }

                    req.body = body;
                    req.raw_body = headers + body;
                } else {
                    req.raw_body = headers;
                }

                if (req.raw_body.empty() || req.raw_body.size() > settings.max_request_size) {
                    return;
                }

                req.ip_address = [&]() -> std::string {
                    if (settings.trust_x_forwarded_for) {
                        for (const auto& it : headers_vec) {
                            if (it.first == "X-Forwarded-For") {
                                auto ips = ssock::utility::split(it.second, ",");
                                for (const auto& ip : ips) {
                                    if (ssock::sock::is_ipv4(ip) || ssock::sock::is_ipv6(ip)) {
                                        return ip;
                                    }
                                }
                            }
                        }
                    }
                    return {};
                }();

                if (req.ip_address.empty()) {
                    req.ip_address = client_sock->get_peer().get_ip();
                }

                if (!ssock::sock::is_ipv4(req.ip_address) && !ssock::sock::is_ipv6(req.ip_address)) {
                    throw parsing_error("invalid IP address: " + req.ip_address);
                }

                if (std::ranges::find(settings.blacklisted_ips, req.ip_address) != settings.blacklisted_ips.end()) {
                    return;
                }

                req.version = [&]() {
                    if (status_line.http_version == "HTTP/1.0") {
                        return 10;
                    } else if (status_line.http_version == "HTTP/1.1") {
                        return 11;
                    } else {
                        throw parsing_error("unsupported HTTP version: " + status_line.http_version);
                    }
                }();
                auto full_path = status_line.path;
                if (full_path.empty() || full_path[0] != '/') {
                    throw parsing_error("invalid path: " + full_path);
                }
                auto query_pos = full_path.find('?');
                if (query_pos != std::string::npos) {
                    req.endpoint = full_path.substr(0, query_pos);
                    auto query_str = full_path.substr(query_pos + 1);
                    req.query = ssock::utility::parse_fields(query_str);
                } else {
                    req.endpoint = full_path;
                }

                req.fields = ssock::utility::parse_fields(req.body);
                for (const auto& it : headers_vec) {
                    if (it.first == "Content-Type") {
                        req.content_type = it.second;
                    } else if (it.first == "User-Agent") {
                        req.user_agent = it.second;
                    } else if (it.first == "Cookie") {
                        req.cookies = get_cookies_from_request(it.second);
                    }
                }

                std::string session_id{};
                bool session_id_found = false;
                for (const auto& it : req.cookies) {
                    if (it.name == settings.session_cookie_name && !it.value.empty() && settings.enable_session) {
                        session_id = it.value;
                        session_id_found = true;
                        break;
                    }
                }

                bool erase_associated = false;
                if (session_id_found) {
                    std::erase(session_id, '/');
                    std::filesystem::path session_file = settings.session_directory + "/session_" + session_id + ".txt";
                    req.session = settings.read_from_session_file(session_file.string());
                    req.session_id = session_id;

                    if (!std::filesystem::exists(session_file)) {
                        erase_associated = true;
                        // remove associated session cookies and session cookie from request
                        for (const auto& it : settings.associated_session_cookies) {
                            req.cookies.erase(
                                std::remove_if(req.cookies.begin(), req.cookies.end(),
                                               [&it](const cookie& cookie) {
                                                   return cookie.name == it;
                                               }),
                                req.cookies.end()
                            );
                        }
                        req.cookies.erase(
                            std::remove_if(req.cookies.begin(), req.cookies.end(),
                                           [this, &settings](const cookie& cookie) {
                                               return cookie.name == settings.session_cookie_name;
                                           }),
                            req.cookies.end()
                        );

                        req.session.clear();
                        req.session_id.clear();
                    } else {
                        req.session = settings.read_from_session_file(session_file.string());
                        req.session_id = session_id;
                    }
                }

                auto response = callback(req);
                std::stringstream net_response;
                net_response << "HTTP/1.1 " << response.http_status << " " << ssock::http::get_http_message(response.http_status).value_or("Unknown") << "\r\n";
                if (!response.content_type.empty()) net_response << "Content-Type: " << response.content_type << "\r\n";
                if (!response.allow_origin.empty()) net_response << "Access-Control-Allow-Origin: " << response.allow_origin << "\r\n";
                if (!response.location.empty()) {
                    net_response << "Location: " << response.location << "\r\n";
                }
                if (!response.headers.empty()) {
                    for (const auto& it : response.headers) {
                        net_response << it.name << ": " << it.data << "\r\n";
                    }
                }
                if (response.redirection == redirect_type::temporary) {
                    net_response << "Cache-Control: no-cache\r\n";
                } else if (response.redirection == redirect_type::permanent) {
                    net_response << "Cache-Control: no-store\r\n";
                }

                if (!session_id_found && settings.enable_session) {
                    session_id = utility::generate_random_string();
                    response.cookies.push_back({.name = settings.session_cookie_name, .value = session_id, .expires = 0, .path = "/", .same_site = "Strict", .http_only = true, .secure = settings.session_is_secure});
                } else if (settings.enable_session) {
                    std::string session_file = settings.session_directory + "/session_" + session_id + ".txt";
                    std::unordered_map<std::string, std::string> stored = settings.read_from_session_file(session_file);

                    for (const auto& it : response.session) {
                        stored[it.first] = it.second;
                    }

                    settings.write_to_session_file(session_file, stored);
                }

                for (const auto& it : response.cookies) {
                    std::string cookie_str = it.name + "=" + it.value + "; ";
                    if (it.expires != 0) {
                        cookie_str += "Expires=" + utility::convert_unix_millis_to_gmt(it.expires) + "; ";
                    } else {
                        cookie_str += "Expires=session; ";
                    }
                    if (it.http_only) {
                        cookie_str += "HttpOnly; ";
                    }
                    if (it.secure) {
                        cookie_str += "Secure; ";
                    }
                    if (!it.path.empty()) {
                        cookie_str += "Path=" + it.path + "; ";
                    }
                    if (!it.domain.empty()) {
                        cookie_str += "Domain=" + it.domain + "; ";
                    }
                    if (!it.same_site.empty() && (it.same_site == "Strict" || it.same_site == "Lax" || it.same_site == "None")) {
                        cookie_str += "SameSite=" + it.same_site + "; ";
                    }
                    for (const auto& attribute : it.attributes) {
                        cookie_str += attribute + "; ";
                    }
                    for (const auto& attribute : it.extra_attributes) {
                        cookie_str += attribute.first + "=" + attribute.second + "; ";
                    }

                    net_response << "Set-Cookie: " << cookie_str << "\r\n";
                }

                if (erase_associated) {
                    for (const auto& it : settings.associated_session_cookies) {
                        response.delete_cookies.push_back(it);
                    }
                }

                for (const auto& it : response.delete_cookies) {
                    std::string cookie_str = it + "=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; ";
                    net_response << "Set-Cookie: " << cookie_str << "\r\n";
                }

                if (response.stop) {
                    return;
                }

                for (const auto& it : response.headers) {
                    net_response << it.name << ": " << it.data << "\r\n";
                }

                net_response << "Connection: close\r\n";

                if (!response.body.empty()) {
                    net_response << "Content-Length: " << response.body.size() << "\r\n";
                }

                net_response << "\r\n";
                net_response << response.body;

                client_sock->send(net_response.str());
                client_sock->close();
            }
        };

        /**
         * @brief  Interface class that represents a server.
         */
        template <typename T = request_handler<>>
        class basic_sync_server {
            public:
                virtual ~basic_sync_server() = default;
                virtual void run() = 0;
                virtual void stop() = 0;
        };

        /**
         * @brief  Class that represents a server.
         */
        template <typename T = request_handler<>>
        class sync_server : basic_sync_server<> {
            bool running = true;
            server_settings settings;
            std::function<response(const request&)> callback;
            std::unique_ptr<sock::sync_sock> sock;
        public:
            /**
             * @brief  Constructor for the server class
             * @param  settings The settings for the server
             * @param  callback The function to call when a request is made
             */
            sync_server(server_settings settings, const std::function<response(const request&)>& callback)
                : settings(std::move(settings)), callback(callback)
            {
                if (!ssock::network::is_valid_port(settings.port)) {
                    throw parsing_error("invalid port");
                }

                sock::sock_addr addr = {"localhost", settings.port, ssock::sock::sock_addr_type::hostname};
                this->sock = std::make_unique<sock::sync_sock>(addr, ssock::sock::sock_type::tcp, ssock::sock::sock_opt::reuse_addr|ssock::sock::sock_opt::no_delay|ssock::sock::sock_opt::blocking);

                try {
                    sock->bind();
                } catch (const std::exception&) {
                    throw socket_error("failed to bind socket, port might be in use");
                }
                sock->listen(settings.max_connections);
            };
            ~sync_server() {
                sock->close();
            }
            /**
             * @brief  Run the server
             */
            void run() override {
                while (running) {
                    auto client_sock = sock->accept();

                    std::thread([client_sock = std::move(client_sock),
                                 settings = this->settings,
                                 callback = this->callback]() mutable {
                        try {
                            T handler{};
                            handler.handle(client_sock, settings, callback);
                        } catch (const std::exception& e) {
                            throw socket_error(e.what());
                        }
                    }).detach();
                }
            }
            /**
             * @brief  Stop the server
             */
            void stop() override {
                running = false;
                sock->close();
            }
        };
    }
}
