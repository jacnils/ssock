#include <iostream>
#include <ssock.hpp>

void handle_dns(const std::string& hostname);

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <hostname>\n";
        return 1;
    }

    try {
        handle_dns(argv[1]);
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "An unknown error occurred.\n";
        return 1;
    }

    return 0;
}

void handle_dns(const std::string& hostname) {
    ssock::network::dns::dns_resolver resolver(hostname);

    // This uses ANY query by default, which retrieves all types of records.
    // Note that this may not be supported by all DNS servers.
    // If you want to query specific types, you can use resolver.query_records(dns_record_type::A), etc.
    auto records = resolver.query_records();
    auto addresses = resolver.resolve_hostname();
    std::cout << "Resolved IPs for " << hostname << ":\n";
    if (addresses.contains_ipv4()) {
        std::cout << "IPv4: " << addresses.get_ipv4() << "\n";
    } else {
        std::cout << "No IPv4 address found.\n";
    }
    if (addresses.contains_ipv6()) {
        std::cout << "IPv6: " << addresses.get_ipv6() << "\n";
    } else {
        std::cout << "No IPv6 address found.\n";
    }

    std::cout << "\n";

    for (const auto& rec : records) {
        std::cout << "Name: " << rec.name << "\n";

        std::visit([]<typename T0>(T0&& data) {
            using T = std::decay_t<T0>;
            if constexpr (std::is_same_v<T, std::monostate>)
                std::cout << "(empty)\n";
            else if constexpr (std::is_same_v<T, ssock::network::dns::a_record_data>) {
                std::cout << "Type: A Record\n";
                std::cout << "Value: " << data.ip.get_ipv4() << "\n";
            } else if constexpr (std::is_same_v<T, ssock::network::dns::aaaa_record_data>) {
                std::cout << "Type: AAAA Record\n";
                std::cout << "Value: " << data.ip.get_ipv6() << "\n";
            } else if constexpr (std::is_same_v<T, ssock::network::dns::cname_record_data>) {
                std::cout << "Type: CNAME Record\n";
                std::cout << "Value: " << data.cname << "\n";
            } else if constexpr (std::is_same_v<T, ssock::network::dns::generic_record_data>) {
                std::cout << "Type: Generic Record (" << data.type << ")\n";
                for (const auto& byte : data.raw) {}
            } else if constexpr (std::is_same_v<T, ssock::network::dns::txt_record_data>) {
                std::cout << "Type: TXT Record\n";
                for (const auto& text : data.text) {
                    std::cout << "Value: " << text << "\n";
                }
            } else if constexpr (std::is_same_v<T, ssock::network::dns::mx_record_data>) {
                std::cout << "Type: MX Record\n";
                std::cout << "Preference: " << data.preference << "\n";
                std::cout << "Exchange: " << data.exchange << "\n";
            } else if constexpr (std::is_same_v<T, ssock::network::dns::ns_record_data>) {
                std::cout << "Type: NS Record\n";
                std::cout << "NS: " << data.ns << "\n";
                // more can be added here as needed
            } else {
                std::cout << "Type: Unknown Record\n";
            }
        }, rec.data);
        std::cout << "---------------------\n";
    }
}