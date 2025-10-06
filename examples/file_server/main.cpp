#include <iostream>
#include <filesystem>
#include <ssock.hpp>

enum class EntryType {
    File,
    Directory,
    Symlink,
};

struct Entry {
    std::string name{};
    std::string full_path{};
    EntryType type{EntryType::File};
};

std::vector<Entry> get_entries_in_directory(const std::string& directory) {
    std::filesystem::path dir{directory};
    std::vector<Entry> entries;
    if (!std::filesystem::exists(dir) || !std::filesystem::is_directory(dir)) {
        std::cerr << "Directory does not exist or is not a directory: " << directory << std::endl;
        return entries;
    }
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        Entry e;
        e.name = entry.path().filename().string();
        e.full_path = entry.path().string();
        if (std::filesystem::is_regular_file(entry)) {
            e.type = EntryType::File;
        } else if (std::filesystem::is_directory(entry)) {
            e.type = EntryType::Directory;
        } else if (std::filesystem::is_symlink(entry)) {
            e.type = EntryType::Symlink;
        }
        entries.push_back(e);
    }
    return entries;
}

std::string root_directory{"/"};
std::string current_directory{"/"};

[[noreturn]] int main() {
    ssock::http::server::sync_server server(
        ssock::http::server::server_settings{
            .port = 1337,
            .enable_session = false,
            .session_directory = "./sessions",
            .session_cookie_name = "ssock-test",
            .trust_x_forwarded_for = false,
        },
        [](const ssock::http::server::request& request) -> ssock::http::server::response {
            ssock::http::server::response response;
            response.http_status = 200;
            response.content_type = "text/html";

            std::string body = "<html><body>";
            body += "<h1>Directory Listing</h1>";
            body += "<ul>";

            if (request.endpoint != "/") {
                body += "<li><a href=\"/$previous\">..</a></li>";
            } else {
                current_directory = root_directory;
            }

            if (request.endpoint == "/$previous") {
                // Go up one directory
                if (current_directory != root_directory) {
                    current_directory = current_directory.substr(0, current_directory.find_last_of('/'));
                    if (current_directory.empty()) {
                        current_directory = root_directory;
                    }
                }
            } else if (request.endpoint != "/" && request.endpoint.at(0) == '/') {
                auto fod = root_directory + request.endpoint.substr(1);

                if (std::filesystem::is_directory(fod)) {
                    current_directory = fod;
                } else {
                    // serve the file
                    std::filesystem::path file_path{fod};
                    if (std::filesystem::exists(file_path) && std::filesystem::is_regular_file(file_path)) {
                        response.body = ssock::utility::read_file(file_path.string());
                        response.content_type = ssock::utility::get_appropriate_content_type(file_path.filename().string());
                        return response;
                    } else {
                        response.http_status = 404;
                        response.body = "<p>404 Not Found</p>";
                        return response;
                    }
                }
            }

            auto entries = get_entries_in_directory(current_directory);
            for (const auto& entry : entries) {
                body += "<li><a href=\"" + entry.full_path + "\">" + entry.name + "</a></li>";
            }

            body += "</ul></body></html>";
            response.body = body;

            return response;
        });

    server.run();
}
