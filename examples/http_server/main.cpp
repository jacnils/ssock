#include <iostream>
#include <ssock.hpp>

int main() {
    constexpr int port = 8081;
    std::cout << "Starting HTTP server on port " << port << "...\n";
    ssock::http::server::sync_server server(
        ssock::http::server::server_settings{
            .port = port,
            .enable_session = false,
            .session_directory = "./sessions",
            .session_cookie_name = "ssock-test",
            .trust_x_forwarded_for = false,
        },
        [](const ssock::http::server::request& req) -> ssock::http::server::response {
            ssock::http::server::response res;
            res.http_status = 200;
            res.body = "<html><body>Hello, World!</body></html>";
            res.content_type = "text/html";
            res.headers.push_back({"X-Test-Header", "TestValue"});

            std::cout << "Received request from: " << req.ip_address << "\n"
                      << "Endpoint: " << req.endpoint << "\n"
                      << "Method: " << req.method << "\n"
                      << "User-Agent: " << req.user_agent << "\n"
                      << "Body: " << req.body << "\n";
            return res;
        });

    std::cout << "Server started on port 8080" << ".\n"
              << "Press Ctrl+C to stop the server.\n";

    server.run();

    return 0;
}
