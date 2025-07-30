/**
 * @file ssock.hpp
 * @brief A simple TCP/UDP and HTTP socket C++ library for Unix-like systems.
 * @license MIT
 * @author Jacob Nilsson
 * @copyright 2025 Jacob Nilsson
 */
#pragma once

#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <unordered_map>
#include <variant>
#include <algorithm>
#include <ranges>

#ifndef SSOCK
#define SSOCK 1
#endif
// SSOCK_DEBUG

#if defined(__unix__) || defined(__unix) || defined(__APPLE__) && defined(__MACH__)
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <unistd.h>
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
 * @brief Namespace for the ssock library.
 * @note Contains network-related classes and functions.
 */
namespace ssock::network {
    namespace dns {
        class dns_resolver;
    };

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
            if (!this->contains_ipv4()) {
                throw ip_error("sock_ip_list(): no IPv4 address");
            }
            return v4;
        }
        [[nodiscard]] std::string get_ipv6() const {
            if (!this->contains_ipv6()) {
                throw ip_error("sock_ip_list(): no IPv6 address");
            }
            return v6;
        }
        [[nodiscard]] std::string get_ip() const {
            if (v4.empty() && v6.empty()) {
                throw ip_error("sock_ip_list(): no IP address");
            }
            return v6.empty() ? v4 : v6;
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
    namespace dns {
        enum class dns_record_type {
            A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, PTR, CAA, OTHER
        };

        struct generic_record_data {
            uint16_t type;
            std::vector<uint8_t> raw;
        };

        struct a_record_data {
            sock_ip_list ip;
        };

        struct aaaa_record_data {
            sock_ip_list ip;
        };

        struct cname_record_data {
            std::string cname;
        };

        struct mx_record_data {
            uint16_t preference;
            std::string exchange;
        };

        struct ns_record_data {
            std::string ns;
        };

        struct txt_record_data {
            std::vector<std::string> text;
        };

        struct soa_record_data {
            std::string mname;
            std::string rname;
            uint32_t serial, refresh, retry, expire, minimum;
        };

        struct srv_record_data {
            uint16_t priority, weight, port;
            std::string target;
        };

        struct ptr_record_data {
            std::string ptrname;
        };

        struct caa_record_data {
            uint8_t flags;
            std::string tag;
            std::string value;
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

        struct dns_record {
            std::string name;
            dns_record_type type{};
            uint16_t record_class = 1;
            uint32_t ttl{};
            dns_record_data data;
        };

        using dns_selector = std::variant<std::monostate, std::string, dns_record_type>;
        class dns_resolver final {
            std::string hostname{};

            void throw_if_invalid() const {
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
            [[nodiscard]] std::vector<dns_record> query_records(const dns_selector& selector = std::monostate{}) const {
                throw_if_invalid();

                int qtype = resolve_query_type(selector);

                res_init();

                u_char response[2048]{};
                int len = res_query(hostname.c_str(), ns_c_in, qtype, response, sizeof(response));
                if (len < 0) {
                    if (h_errno == NO_DATA) {
                        std::cerr << "No " << ((qtype == ns_t_a) ? "A" : "requested")
                                  << " record found for: " << hostname << std::endl;
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

        };
    }

    /**
     * @brief A function that gets the local network interfaces.
     * @return A vector of network_interface structs that contain the local network interfaces.
     */
    inline std::vector<network_interface> get_interfaces();
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
     * @brief Get a list of all network interfaces on the system.
     * @return A vector of network_interface objects.
     * @throws std::runtime_error if getifaddrs() fails.
     */
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
        for (auto& [fst, snd] : iface_map) {
            list.emplace_back(std::move(snd));
        }

        return list;
    }
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
    using sock_fd_t = int;
    using sock_addr_type = network::sock_addr_type;

    /**
     * @brief Socket types.
     */
    enum class sock_type {
        tcp, /* TCP socket */
        udp, /* UDP socket */
    };
    /**
     * @brief Socket options.
     * @note These options can be used with the sync_sock class to set socket options.
     */
    enum class sock_opt {
        reuse_addr = 1 << 0, /* Reuse address option */
        no_reuse_addr = 1 << 1, /* Do not reuse address option */
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
    static sock_addr get_peer(int sockfd);
    /**
     * @brief A class that represents a socket address.
     * @param hostname The hostname or IP address to resolve.
     * @param port The port to use.
     * @param t The address type (ipv4, ipv6, hostname_ipv4, hostname_ipv6).
     */
    class sock_addr final {
        std::string hostname{};
        std::string ip{};
        int port{};
        sock_addr_type type{sock_addr_type::hostname};
        friend sock_addr get_peer(int);

        sock_addr() = default;
    public:
        /**
         * @brief Constructs a sock_addr object.
         * @param hostname The hostname or IP address to resolve.
         * @param port The port to use.
         * @param t The address type (ipv4, ipv6, hostname_ipv4, hostname_ipv6).
         */
        sock_addr(const std::string& hostname, int port, sock_addr_type t) : hostname(hostname), port(port), type(t) {
            const auto resolve_host = [](const std::string& h, int p, bool t) -> std::string {
                try {
                    network::dns::dns_resolver resolver(h);
                    auto ip_list = resolver.resolve_hostname(p);
                    return t ? ip_list.get_ipv6() : ip_list.get_ipv4();
                } catch (const std::exception&) {
                    return {};
                }
            };

            if (type == sock_addr_type::hostname) {
                ip = resolve_host(hostname, port, true);
                type = ssock::sock::sock_addr_type::ipv6;

                if (!ssock::network::usable_ipv6_address_exists()) {
                    ip.clear();
                }

                if (ip.empty()) {
                    ip = resolve_host(hostname, port, false);
                    type = ssock::sock::sock_addr_type::ipv4;
                }
            } else if (type == sock_addr_type::hostname_ipv4) {
                ip = resolve_host(hostname, port, false);
                type = ssock::sock::sock_addr_type::ipv4;
            } else if (type == sock_addr_type::hostname_ipv6) {
                ip = resolve_host(hostname, port, true);
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
                throw parsing_error("hostname is empty, use get_ip() instead");
            }
            return hostname;
        }
        /**
         * @brief Get the stored hostname.
         * @return The stored hostname.
         */
        [[nodiscard]] std::string get_hostname() const {
            if (hostname.empty()) {
                throw parsing_error("hostname is empty, use get_ip() instead");
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

    /**
     * @brief A class that represents a synchronous socket.
     * @note This class is an abstract base class and should not be instantiated directly.
     * @note Use the sync_sock class instead.
     */
    class basic_sync_sock {
      public:
        basic_sync_sock() = default;
        virtual ~basic_sync_sock() = default;
        basic_sync_sock(const basic_sync_sock&) = delete;

        virtual void connect() = 0;
        virtual void bind() = 0;
        virtual void unbind() = 0;
        virtual void listen(int backlog) = 0;
        virtual std::unique_ptr<sync_sock> accept() = 0;
        virtual int send(const void* buf, size_t len) = 0;
        virtual void send(const std::string& buf) = 0;
        [[nodiscard]] virtual std::string recv(int timeout_seconds) const = 0;
        [[nodiscard]] virtual std::string recv(int timeout_seconds, const std::string& match) const = 0;
        virtual void close() = 0;
    };

    /**
     * @brief A class that represents a synchronous socket.
     */
    class sync_sock : basic_sync_sock {
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
            } else {
                throw ip_error("invalid address type");
            }
        }
    public:
        /**
         * @brief Constructs a sync_sock object.
         * @param addr The socket address to bind to.
         * @param t The socket type (tcp or udp).
         * @param opts The socket options (reuse_addr, no_reuse_addr).
         */
        sync_sock(const sock_addr& addr, sock_type t, sock_opt opts = sock_opt::no_reuse_addr) : addr(addr), type(t) {
            if (addr.get_ip().empty()) {
                throw socket_error("IP address is empty");
            }

            this->sockfd = internal_net::sys_net_socket(addr.is_ipv6() ? AF_INET6 : AF_INET,
                                                              t == sock_type::tcp ? SOCK_STREAM : SOCK_DGRAM, 0);

            if (this->sockfd < 0) {
                throw socket_error("failed to create socket");
            }

            if (opts & sock_opt::reuse_addr) {
                internal_net::sys_net_setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opts, sizeof(opts));
            } else if (opts & sock_opt::no_reuse_addr) {
                internal_net::sys_net_setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, nullptr, 0);
            }

            this->prep_sa();
        }

        ~sync_sock() override {
            internal_net::sys_net_close(sockfd);
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
        void connect() override {
            if (internal_net::sys_net_connect(this->sockfd, this->get_sa(), this->get_sa_len()) < 0) {
                throw socket_error("failed to connect to server");
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

            auto ret = internal_net::sys_net_bind(this->sockfd, this->get_sa(), this->get_sa_len());

            if (ret < 0) {
                throw socket_error("failed to bind socket: " + std::to_string(ret));
            }
        }
        /**
         * @brief Unbind the socket from the address.
         */
        void unbind() override {
            if (this->bound) {
                if (internal_net::sys_net_close(this->sockfd) < 0) {
                    throw socket_error("failed to unbind socket");
                }
                this->bound = false;
            }
        }
        /**
         * @brief Listen for incoming connections.
         * @param backlog The maximum number of pending connections (default is 5).
         * @note Very barebones, use with care.
         */
        void listen(int backlog) override {
            if (internal_net::sys_net_listen(this->sockfd, backlog) < 0) {
                throw socket_error("failed to listen on socket");
            }
        }
        /**
         * @brief Accept a connection from a client.
         * @return sock_handle The socket handle for the accepted connection.
         */
        [[nodiscard]] std::unique_ptr<sync_sock> accept() override {
            sockaddr_storage client_addr{};
            socklen_t addr_len = sizeof(client_addr);

            int client_sockfd = internal_net::sys_net_accept(this->sockfd, reinterpret_cast<sockaddr*>(&client_addr), &addr_len);
            if (client_sockfd < 0) {
                throw socket_error("failed to accept connection: " + std::string(strerror(errno)));
            }

            auto peer = sock::get_peer(client_sockfd);
            auto handle = std::make_unique<sync_sock>(peer, this->type);
            handle->sockfd = client_sockfd;

            return handle;
        }
        /**
         * @brief Send data to the server.
         * @param buf The data to send.
         * @param len The length of the data.
         * @return The number of bytes sent.
         */
        int send(const void* buf, size_t len) override {
            std::size_t ret = internal_net::sys_net_send(this->sockfd, buf, len, 0);
            return static_cast<int>(ret);
        }
        /**
         * @brief Send a string to the server.
         * @param buf The string to send.
         */
        void send(const std::string& buf) override {
            static_cast<void>(this->send(buf.c_str(), buf.length()));
        }
        /**
         * @brief Receive data from the server.
         * @param timeout_seconds The timeout in seconds (-1 means wait indefinitely until match is found)
         * @param match The substring to look for in received data.
         * @return The received data as a string.
         */
        [[nodiscard]] std::string recv(const int timeout_seconds, const std::string& match) const override {
            std::string data;
            auto start = std::chrono::steady_clock::now();

            while (true) {
                fd_set readfds;
                FD_ZERO(&readfds);
                FD_SET(this->sockfd, &readfds);

                timeval tv{};
                timeval* tv_ptr = nullptr;

                if (timeout_seconds >= 0) {
                    auto now = std::chrono::steady_clock::now();
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start).count();
                    auto remaining = timeout_seconds - elapsed;
                    if (remaining <= 0) {
                        break;
                    }
                    tv.tv_sec = remaining;
                    tv.tv_usec = 0;
                    tv_ptr = &tv;
                }

                int ret = internal_net::sys_net_select(this->sockfd + 1, &readfds, nullptr, nullptr, tv_ptr);

                if (ret < 0) {
                    throw socket_error("select() failed");
                }
                if (ret == 0) {
                    continue;
                }

                if (FD_ISSET(this->sockfd, &readfds)) {
                    char buf[1024];
                    std::size_t received = internal_net::sys_net_recv(this->sockfd, buf, sizeof(buf), 0);
                    if (received == 0) {
                        break;
                    }
                    data.append(buf, received);

                    if (data.find_last_of(match) != std::string::npos && !match.empty()) {
                        break;
                    }
                }
            }

            return data;
        }
        /* @brief Receive data from the server.
         * @param timeout_seconds The timeout in seconds (-1 means wait indefinitely).
         * @return The received data as a string.
         */
        [[nodiscard]] std::string recv(const int timeout_seconds) const override {
            return recv(timeout_seconds, "");
        }

        /**
         * @brief Close the socket.
         */
        void close() override {
            if (!this->sockfd) {
                throw socket_error("socket is not initialized");
            }
            if (internal_net::sys_net_close(this->sockfd) < 0) {
                throw socket_error("failed to close socket");
            }
        }
        [[nodiscard]] sock_addr get_peer() const {
            return ssock::sock::get_peer(this->sockfd);
        }
    };
    sock_addr get_peer(int sockfd);
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

        return {std::move(v4), std::move(v6)};
    }
    static sock_addr get_peer(int sockfd) {
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
        std::vector<std::pair<std::string, std::string>> headers{};
    };

    template <typename T = std::istringstream, typename R = response, typename VPS = std::vector<std::pair<T,T>>>
    class basic_body_parser {
        T& input;
        R ret{};
        VPS headers{};
        T body{};
    public:
        explicit basic_body_parser(T& input) : input(input), ret({}) {}
        explicit basic_body_parser() = default;
        virtual ~basic_body_parser() = default;
        virtual VPS& get_headers() = 0;
        virtual T& get_body() = 0;
        virtual T& get_input() = 0;
        virtual T decode_chunked(const std::string& encoded) = 0;
        virtual int get_status_code() = 0;
        virtual R& parse() = 0;
    };

    /**
     * @brief Basic HTTP body parser.
     * @note Splits the body into headers and body.
     */
    template <typename T = std::istringstream,
              typename R = response,
              typename VPS = std::vector<std::pair<T,T>>>
    class body_parser : basic_body_parser<T, R> {
        T& input;
        R ret{};
        VPS headers{};
        T body{};
    public:
        /**
         * @brief Constructs a basic_body_parser object.
         * @param input The body to parse.
         */
        explicit body_parser(T& input) : basic_body_parser<T,R,VPS>(input), input(input), ret({}) {
            constexpr auto HEADER_END = "\r\n\r\n";
            const auto pos = input.find(HEADER_END);
            if (pos == std::string::npos) {
                throw parsing_error("no header terminator");
            }
            this->body = input.substr(pos + strlen(HEADER_END));

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
        ~body_parser() override = default;

        /**
         * @brief Decode chunked transfer encoding.
         * @param encoded The encoded string.
         * @return The decoded string.
         */
        [[nodiscard]] T decode_chunked(const std::string& encoded) override {
            T dec;
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
         * @brief Get the status code from the response.
         * @return The status code.
         */
        [[nodiscard]] int get_status_code() override {
            if (input.find("HTTP/") == std::string::npos) {
                throw parsing_error("failed to parse status code");
            }
            std::string line{};
            if (input.find('\n') != std::string::npos) {
                line = input.substr(0, input.find('\n'));
            } else {
                line = input;
            }

            if (line.empty()) {
                throw parsing_error("failed to parse status code");
            }

            if (line.back() == '\r') line.pop_back();

            std::istringstream iss(line);
            std::string version{};

            int status_code{};

            iss >> version >> status_code;

            if (iss.fail()) {
                throw parsing_error("failed to parse status code");
            }

            if (status_code < 100 || status_code > 599) {
                throw parsing_error("invalid status code");
            }

            return status_code;
        }
        /**
         * @brief Get the input stream.
         * @return The input stream (reference)
         */
        [[nodiscard]] T& get_input() override {
            return this->input;
        }
        /**
         * @brief Get the body (excluding any headers)
         */
        [[nodiscard]] T& get_body() override {
            return this->body;
        }
        /**
         * @brief Get the headers.
         * @return The headers (reference)
         */
        [[nodiscard]] VPS& get_headers() override {
            return this->headers;
        }
        /**
         * @brief Parse the body.
         * @return The parsed response (reference)
         */
        [[nodiscard]] R& parse() override {
            this->ret = R{};
            this->ret.status_code = get_status_code();
            this->ret.headers = get_headers();
            this->ret.body = get_body();

            // handle chunked
            bool is_enc{false};
            for (const auto& [key, val] : ret.headers) {
                if (key == "Transfer-Encoding" && val.find("chunked") != std::string::npos) {
                    ret.body = std::move(decode_chunked(input));
                    is_enc = true;
                    break;
                }
            }

            if (!is_enc) {
                ret.body = input;
            }

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
        int timeout{-1};

        [[nodiscard]] std::string make_request(const std::string& request) const noexcept {
            sock::sock_addr addr(hostname, port, sock::sock_addr_type::hostname_ipv4);
            sock::sync_sock sock(addr, sock::sock_type::tcp);
            sock.connect();
            sock.send(request);
            return sock.recv(this->timeout, "\r\n\r\n");
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
        template <typename T = body_parser<std::string>>
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

            T parser(ret);

            return parser.parse();
        }
    };
}