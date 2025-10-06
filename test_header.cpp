#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <fstream>
#include <ssock.hpp>

void test_socket() {
    const auto addr = ssock::sock::sock_addr("google.com", 80, ssock::sock::sock_addr_type::hostname);
    auto sock = ssock::sock::sync_sock(addr, ssock::sock::sock_type::tcp);

    sock.connect();
    sock.send("GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n");
    std::string response = sock.recv(-1).data;
    std::cout << response << std::endl;
}

void test_http_server() {
    ssock::sock::sock_addr addr = {"127.0.0.1", 8081, ssock::sock::sock_addr_type::ipv4};
    ssock::sock::sync_sock sock{addr, ssock::sock::sock_type::tcp, ssock::sock::sock_opt::reuse_addr};

    // bind the socket
    sock.bind();
    sock.listen(-1);

    while (true) {
        // accept a new connection
        auto client_sock = sock.accept();
        std::cout << "New connection accepted." << std::endl;
        try {
            // receive data from the client
            std::string request = client_sock->recv(-1, "\r\n\r\n").data;
            std::cout << "Received request:\n" << request << std::endl;

            // send a simple HTTP response
            std::string response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nHello, World client " + // random identifier
                                   std::to_string(rand() % 1000) + "!\r\n\r\n";
            client_sock->send(response);
            client_sock->close();
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
        }
    }
}

void test_http_abstr() {
    ssock::http::client client{"127.0.0.1", "/", 8081, ssock::http::method::GET, ssock::http::version::HTTP_1_1};
    client.set_body("<html><body>Hello, World!</body></html>");
    client.set_header("Content-Type", "text/html");
    client.set_header("User-Agent", "ssock-test/1.0");
    client.set_connection("close");
    client.append_headers({{"X-Test-Header", "TestValue"}});
    auto response = client.get();
    // write our request to a file
    std::ofstream request_file("http_request.txt");
    request_file << client.get_body();
    request_file.close();
    // write our response to a file
    std::ofstream response_file("http_response.txt");
    std::cout << "HTTP headers:\n";
    for (const auto& header : response.headers) {
        std::cout << header.first << ": " << header.second << std::endl;
        response_file << header.first << ": " << header.second << std::endl;
    }
    std::cout << "HTTP body:\n" << response.body << std::endl;
    response_file << response.body;
    response_file.close();
}

void test_http_abstr_2() {
    ssock::http::server::sync_server server(ssock::http::server::server_settings{
        .port = 8080,
        .enable_session = true,
        .session_directory = "./sessions",
        .session_cookie_name = "ssock-test",
        .trust_x_forwarded_for = false,
    }, [](const ssock::http::server::request& req) -> ssock::http::server::response {
        ssock::http::server::response res;
        res.http_status = 200;
        res.body = "<html><body>Hello, World!</body></html>";
        res.content_type = "text/html";
        res.headers.push_back({"X-Test-Header", "TestValue"});

        // write log message to console
        std::cout << "Received request from: " << req.ip_address << "\n"
                  << "Endpoint: " << req.endpoint << "\n"
                  << "Method: " << req.method << "\n"
                  << "User-Agent: " << req.user_agent << "\n";
        return res;
    });

    server.run();
}

void test_get_dns_nameservers(const std::string& hostname) {
    auto nameservers = ssock::network::dns::get_nameservers();

    std::cout << "Standard location:\n";
    std::cout << ssock::utility::get_standard_cache_location() << "\n";
    std::cout << "Nameservers:\n";
    if (nameservers.contains_ipv4()) {
        for (const auto& it : nameservers.get_ipv4()) {
            std::cout << "IPv4: " << it << "\n";
        }
    }
    if (nameservers.contains_ipv6()) {
        for (const auto& it : nameservers.get_ipv6()) {
            std::cout << "IPv6: " << it << "\n";
        }
    }

    /* overriding:
    nameservers = ssock::network::dns::dns_nameserver_list{
        {"8.8.8.8"}, {}
    };
    */

    ssock::network::dns::sync_dns_resolver resolver(nameservers);
    auto types = std::vector<ssock::network::dns::dns_record_type> {
        ssock::network::dns::dns_record_type::A,
        ssock::network::dns::dns_record_type::AAAA,
        ssock::network::dns::dns_record_type::CNAME,
        ssock::network::dns::dns_record_type::TXT,
        ssock::network::dns::dns_record_type::MX,
        ssock::network::dns::dns_record_type::NS,
    };

    for (const auto& type : types) {
        std::vector<ssock::network::dns::dns_record> records;
        try {
            records = resolver.query_records(hostname, type);
        } catch (const ssock::dns_error& e) {
            // probably means no records
            continue;
        }

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
                }
            }, rec.data);
            std::cout << "---------------------\n";
        }
    }
}

void test_dns_any(const std::string& hostname = "google.com", ssock::network::dns::dns_record_type type = ssock::network::dns::dns_record_type::ANY) {
    auto nameservers = ssock::network::dns::get_nameservers();
    nameservers = ssock::network::dns::dns_nameserver_list{
            {"8.8.8.8"}, {}
    };
    ssock::network::dns::sync_dns_resolver resolver(nameservers);

    auto records = resolver.query_records(hostname, type);

    std::cout << "ANY Records for " << hostname << ":\n";
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
            }
        }, rec.data);
        std::cout << "---------------------\n";
    }
}

/*
int main() {
   std::cout << "ssock.hpp" << std::endl;
   test_socket();
   test_dns("google.com");
   test_dns("forwarderfactory.com");
   test_dns("jacobnilsson.com");
   test_dns_steps("google.com");
   test_dns_steps("forwarderfactory.com");
   test_dns_steps("jacobnilsson.com");

   std::thread server_thread([]() {
       try {
           test_http_server();
       } catch (const std::exception& e) {
           std::cerr << "HTTP Server Error: " << e.what() << std::endl;
       }
   });
   server_thread.detach();
   std::this_thread::sleep_for(std::chrono::seconds(1)); // give the server time to start
   test_http_abstr();

   test_get_dns_nameservers("google.com");
   test_get_dns_nameservers("forwarderfactory.com");

   test_dns_any("google.com", ssock::network::dns::dns_record_type::A);
   test_dns_any("google.com", ssock::network::dns::dns_record_type::AAAA);
   test_dns_any("google.com", ssock::network::dns::dns_record_type::TXT);
   std::cout << "---- END OF CLIENT TESTS ----" << std::endl;

   test_http_abstr_2();

   return EXIT_SUCCESS;
}
*/
int main() {
    test_get_dns_nameservers("google.com");
    test_get_dns_nameservers("forwarderfactory.com");
    test_get_dns_nameservers("jacobnilsson.com");
    test_get_dns_nameservers("github.com");
}
