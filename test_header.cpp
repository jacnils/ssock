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

void test_dns(const std::string& hostname = "google.com") {
    ssock::network::dns::dns_resolver resolver(hostname);
    auto records = resolver.query_records(); // ANY query

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

int main() {
    std::cout << "ssock.hpp" << std::endl;
    test_socket();
    test_dns("google.com");
    test_dns("forwarderfactory.com");
    test_dns("jacobnilsson.com");
}