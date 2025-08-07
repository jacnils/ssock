#include <iostream>
#include <fstream>
#include <ssock.hpp>

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
    thin_http_abstraction();
}