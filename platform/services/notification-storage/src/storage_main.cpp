#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>

namespace {

struct HttpRequest {
  std::string method;
  std::string path;
  std::unordered_map<std::string, std::string> headers;
  std::string body;
};

std::optional<int> ParseIntEnv(const char* key, int fallback) {
  const char* value = std::getenv(key);
  if (value == nullptr) {
    return fallback;
  }
  try {
    return std::stoi(value);
  } catch (...) {
    return std::nullopt;
  }
}

std::string Trim(const std::string& input) {
  size_t start = 0;
  while (start < input.size() && std::isspace(static_cast<unsigned char>(input[start]))) {
    ++start;
  }
  size_t end = input.size();
  while (end > start && std::isspace(static_cast<unsigned char>(input[end - 1]))) {
    --end;
  }
  return input.substr(start, end - start);
}

std::string ToLower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return s;
}

bool SendAll(int fd, const std::string& data) {
  size_t sent = 0;
  while (sent < data.size()) {
    ssize_t n = send(fd, data.data() + sent, data.size() - sent, 0);
    if (n <= 0) {
      return false;
    }
    sent += static_cast<size_t>(n);
  }
  return true;
}

bool ReadExact(int fd, std::string& out, size_t len) {
  out.clear();
  out.reserve(len);
  while (out.size() < len) {
    char buf[1024];
    size_t to_read = std::min(sizeof(buf), len - out.size());
    ssize_t n = recv(fd, buf, to_read, 0);
    if (n <= 0) {
      return false;
    }
    out.append(buf, static_cast<size_t>(n));
  }
  return true;
}

bool ReadHttpRequest(int fd, HttpRequest& request) {
  std::string raw;
  char buf[4096];
  size_t header_end = std::string::npos;

  while ((header_end = raw.find("\r\n\r\n")) == std::string::npos) {
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) {
      return false;
    }
    raw.append(buf, static_cast<size_t>(n));
    if (raw.size() > 1024 * 1024) {
      return false;
    }
  }

  const std::string headers_part = raw.substr(0, header_end);
  std::string body_part = raw.substr(header_end + 4);

  std::istringstream stream(headers_part);
  std::string request_line;
  if (!std::getline(stream, request_line)) {
    return false;
  }
  if (!request_line.empty() && request_line.back() == '\r') {
    request_line.pop_back();
  }

  std::istringstream req_line_stream(request_line);
  std::string version;
  if (!(req_line_stream >> request.method >> request.path >> version)) {
    return false;
  }

  std::string line;
  while (std::getline(stream, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    size_t colon = line.find(':');
    if (colon == std::string::npos) {
      continue;
    }
    request.headers[ToLower(Trim(line.substr(0, colon)))] = Trim(line.substr(colon + 1));
  }

  size_t content_length = 0;
  auto it = request.headers.find("content-length");
  if (it != request.headers.end()) {
    try {
      content_length = static_cast<size_t>(std::stoul(it->second));
    } catch (...) {
      return false;
    }
  }

  request.body = body_part;
  if (request.body.size() < content_length) {
    std::string remaining;
    if (!ReadExact(fd, remaining, content_length - request.body.size())) {
      return false;
    }
    request.body += remaining;
  } else if (request.body.size() > content_length) {
    request.body.resize(content_length);
  }

  return true;
}

void WriteHttpResponse(int fd, int status, const std::string& status_text, const std::string& body) {
  std::ostringstream resp;
  resp << "HTTP/1.1 " << status << " " << status_text << "\r\n";
  resp << "Content-Type: application/json\r\n";
  resp << "Content-Length: " << body.size() << "\r\n";
  resp << "Connection: close\r\n\r\n";
  resp << body;
  SendAll(fd, resp.str());
}

std::optional<std::string> ExtractJsonStringField(const std::string& json, const std::string& key) {
  const std::string needle = "\"" + key + "\"";
  size_t k = json.find(needle);
  if (k == std::string::npos) {
    return std::nullopt;
  }
  size_t colon = json.find(':', k + needle.size());
  if (colon == std::string::npos) {
    return std::nullopt;
  }
  size_t q1 = json.find('"', colon + 1);
  if (q1 == std::string::npos) {
    return std::nullopt;
  }
  size_t q2 = q1 + 1;
  for (; q2 < json.size(); ++q2) {
    if (json[q2] == '"' && json[q2 - 1] != '\\') {
      break;
    }
  }
  if (q2 >= json.size()) {
    return std::nullopt;
  }
  return json.substr(q1 + 1, q2 - q1 - 1);
}

bool AppendRecord(const std::string& file_path, const std::string& payload) {
  std::ofstream out(file_path, std::ios::app);
  if (!out.is_open()) {
    return false;
  }
  std::time_t now = std::time(nullptr);
  out << "{\"ts\":" << static_cast<long long>(now) << ",\"record\":" << payload << "}\n";
  return true;
}

int CreateServerSocket(int port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    return -1;
  }
  int opt = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(static_cast<uint16_t>(port));
  if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
    close(fd);
    return -1;
  }
  if (listen(fd, 128) < 0) {
    close(fd);
    return -1;
  }
  return fd;
}

}  // namespace

int main() {
  const auto port_opt = ParseIntEnv("STORAGE_PORT", 8090);
  if (!port_opt.has_value()) {
    std::cerr << "invalid STORAGE_PORT\n";
    return 1;
  }

  const int port = port_opt.value();
  const std::string storage_file =
      std::getenv("STORAGE_DATA_FILE") ? std::getenv("STORAGE_DATA_FILE")
                                       : "/tmp/notification_storage.log";

  int server_fd = CreateServerSocket(port);
  if (server_fd < 0) {
    std::cerr << "failed to bind storage on port " << port << ": " << std::strerror(errno) << "\n";
    return 1;
  }

  std::cout << "notification-storage listening on :" << port
            << " file=" << storage_file << "\n";

  while (true) {
    sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(server_fd, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
    if (client_fd < 0) {
      continue;
    }

    HttpRequest req;
    if (!ReadHttpRequest(client_fd, req)) {
      WriteHttpResponse(client_fd, 400, "Bad Request", "{\"error\":\"invalid request\"}");
      close(client_fd);
      continue;
    }

    if (req.method == "GET" && req.path == "/health") {
      WriteHttpResponse(client_fd, 200, "OK", "{\"status\":\"ok\"}");
      close(client_fd);
      continue;
    }

    if (req.method != "POST" || req.path != "/v1/internal/store") {
      WriteHttpResponse(client_fd, 404, "Not Found", "{\"error\":\"route not found\"}");
      close(client_fd);
      continue;
    }

    const auto tenant = ExtractJsonStringField(req.body, "tenant_id");
    const auto status = ExtractJsonStringField(req.body, "status");
    const auto notification_id = ExtractJsonStringField(req.body, "notification_id");
    if (!tenant.has_value() || !status.has_value() || !notification_id.has_value()) {
      WriteHttpResponse(client_fd, 400, "Bad Request",
                        "{\"error\":\"tenant_id, status and notification_id are required\"}");
      close(client_fd);
      continue;
    }

    if (!AppendRecord(storage_file, req.body)) {
      WriteHttpResponse(client_fd, 500, "Internal Server Error",
                        "{\"error\":\"failed to persist record\"}");
      close(client_fd);
      continue;
    }

    WriteHttpResponse(client_fd, 200, "OK", "{\"status\":\"stored\"}");
    close(client_fd);
  }

  close(server_fd);
  return 0;
}
