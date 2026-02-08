#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

struct HttpRequest {
  std::string method;
  std::string path;
  std::unordered_map<std::string, std::string> headers;
  std::string body;
};

std::string ToLower(std::string input) {
  std::transform(input.begin(), input.end(), input.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return input;
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

std::optional<std::string> ExtractJsonStringField(const std::string& json,
                                                  const std::string& field) {
  const std::string needle = "\"" + field + "\"";
  size_t key = json.find(needle);
  if (key == std::string::npos) {
    return std::nullopt;
  }
  size_t colon = json.find(':', key + needle.size());
  if (colon == std::string::npos) {
    return std::nullopt;
  }
  size_t first_quote = json.find('"', colon + 1);
  if (first_quote == std::string::npos) {
    return std::nullopt;
  }
  size_t second_quote = first_quote + 1;
  for (; second_quote < json.size(); ++second_quote) {
    if (json[second_quote] == '"' && json[second_quote - 1] != '\\') {
      break;
    }
  }
  if (second_quote >= json.size()) {
    return std::nullopt;
  }
  return json.substr(first_quote + 1, second_quote - first_quote - 1);
}

std::optional<std::string> ExtractBearerToken(
    const std::unordered_map<std::string, std::string>& headers) {
  auto it = headers.find("authorization");
  if (it == headers.end()) {
    return std::nullopt;
  }
  const std::string& value = it->second;
  const std::string prefix = "Bearer ";
  if (value.rfind(prefix, 0) != 0) {
    return std::nullopt;
  }
  return value.substr(prefix.size());
}

std::optional<std::string> Base64UrlDecode(const std::string& input) {
  std::string normalized = input;
  std::replace(normalized.begin(), normalized.end(), '-', '+');
  std::replace(normalized.begin(), normalized.end(), '_', '/');
  while (normalized.size() % 4 != 0) {
    normalized.push_back('=');
  }

  static const std::string chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::vector<int> map(256, -1);
  for (size_t i = 0; i < chars.size(); ++i) {
    map[static_cast<unsigned char>(chars[i])] = static_cast<int>(i);
  }

  std::string output;
  int val = 0;
  int bits = -8;
  for (unsigned char c : normalized) {
    if (std::isspace(c)) {
      continue;
    }
    if (c == '=') {
      break;
    }
    if (map[c] < 0) {
      return std::nullopt;
    }
    val = (val << 6) + map[c];
    bits += 6;
    if (bits >= 0) {
      output.push_back(static_cast<char>((val >> bits) & 0xFF));
      bits -= 8;
    }
  }
  return output;
}

std::optional<std::string> ExtractTenantFromJwt(
    const std::unordered_map<std::string, std::string>& headers) {
  auto token = ExtractBearerToken(headers);
  if (!token.has_value()) {
    return std::nullopt;
  }

  size_t first_dot = token->find('.');
  if (first_dot == std::string::npos) {
    return std::nullopt;
  }
  size_t second_dot = token->find('.', first_dot + 1);
  if (second_dot == std::string::npos) {
    return std::nullopt;
  }

  auto payload = Base64UrlDecode(token->substr(first_dot + 1, second_dot - first_dot - 1));
  if (!payload.has_value()) {
    return std::nullopt;
  }

  auto tenant = ExtractJsonStringField(payload.value(), "tenant_id");
  if (tenant.has_value()) {
    return tenant;
  }
  return ExtractJsonStringField(payload.value(), "tid");
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

bool ReadExact(int fd, std::string& out, size_t bytes) {
  out.clear();
  out.reserve(bytes);
  while (out.size() < bytes) {
    char buffer[1024];
    size_t remaining = bytes - out.size();
    size_t to_read = std::min(remaining, sizeof(buffer));
    ssize_t n = recv(fd, buffer, to_read, 0);
    if (n <= 0) {
      return false;
    }
    out.append(buffer, static_cast<size_t>(n));
  }
  return true;
}

bool ReadHttpRequest(int client_fd, HttpRequest& request) {
  std::string raw;
  char buf[4096];
  size_t header_end = std::string::npos;

  while ((header_end = raw.find("\r\n\r\n")) == std::string::npos) {
    ssize_t n = recv(client_fd, buf, sizeof(buf), 0);
    if (n <= 0) {
      return false;
    }
    raw.append(buf, static_cast<size_t>(n));
    if (raw.size() > 1024 * 1024) {
      return false;
    }
  }

  std::string headers_part = raw.substr(0, header_end);
  std::string body_part = raw.substr(header_end + 4);

  std::istringstream stream(headers_part);
  std::string request_line;
  if (!std::getline(stream, request_line)) {
    return false;
  }
  if (!request_line.empty() && request_line.back() == '\r') {
    request_line.pop_back();
  }

  std::istringstream line_stream(request_line);
  std::string http_version;
  if (!(line_stream >> request.method >> request.path >> http_version)) {
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
    std::string key = ToLower(Trim(line.substr(0, colon)));
    std::string value = Trim(line.substr(colon + 1));
    request.headers[key] = value;
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
    if (!ReadExact(client_fd, remaining, content_length - request.body.size())) {
      return false;
    }
    request.body += remaining;
  } else if (request.body.size() > content_length) {
    request.body.resize(content_length);
  }

  return true;
}

void WriteHttpResponse(int client_fd, int status, const std::string& status_text,
                       const std::string& body) {
  std::ostringstream response;
  response << "HTTP/1.1 " << status << " " << status_text << "\r\n";
  response << "Content-Type: application/json\r\n";
  response << "Content-Length: " << body.size() << "\r\n";
  response << "Connection: close\r\n";
  response << "\r\n";
  response << body;
  SendAll(client_fd, response.str());
}

std::string RedisRespArray(const std::vector<std::string>& args) {
  std::ostringstream oss;
  oss << "*" << args.size() << "\r\n";
  for (const auto& arg : args) {
    oss << "$" << arg.size() << "\r\n" << arg << "\r\n";
  }
  return oss.str();
}

bool ReadRedisSimpleReply(int fd, std::string& out_reply) {
  out_reply.clear();
  char prefix = '\0';
  if (recv(fd, &prefix, 1, 0) != 1) {
    return false;
  }
  out_reply.push_back(prefix);

  auto read_line = [&](std::string& line) -> bool {
    line.clear();
    char ch = '\0';
    char prev = '\0';
    while (true) {
      ssize_t n = recv(fd, &ch, 1, 0);
      if (n != 1) {
        return false;
      }
      line.push_back(ch);
      if (prev == '\r' && ch == '\n') {
        line.pop_back();
        line.pop_back();
        return true;
      }
      prev = ch;
    }
  };

  std::string line;
  if (!read_line(line)) {
    return false;
  }
  out_reply += line;

  if (prefix == '$') {
    int len = -1;
    try {
      len = std::stoi(line);
    } catch (...) {
      return false;
    }
    if (len < 0) {
      return true;
    }
    std::string payload;
    if (!ReadExact(fd, payload, static_cast<size_t>(len + 2))) {
      return false;
    }
    out_reply += payload;
  }
  return true;
}

bool PublishToRedisStream(const std::string& host, int port, const std::string& stream_name,
                          const std::unordered_map<std::string, std::string>& fields,
                          std::string& reply) {
  int redis_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (redis_fd < 0) {
    return false;
  }

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<uint16_t>(port));
  if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
    close(redis_fd);
    return false;
  }
  if (connect(redis_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
    close(redis_fd);
    return false;
  }

  std::vector<std::string> command = {"XADD", stream_name, "*"};
  for (const auto& [k, v] : fields) {
    command.push_back(k);
    command.push_back(v);
  }

  const std::string payload = RedisRespArray(command);
  bool ok = SendAll(redis_fd, payload) && ReadRedisSimpleReply(redis_fd, reply);
  close(redis_fd);
  return ok;
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
  const auto port_value = ParseIntEnv("GATEWAY_PORT", 8080);
  const auto redis_port_value = ParseIntEnv("REDIS_PORT", 6379);
  if (!port_value.has_value() || !redis_port_value.has_value()) {
    std::cerr << "Invalid numeric environment value.\n";
    return 1;
  }

  const int port = port_value.value();
  const int redis_port = redis_port_value.value();
  const std::string redis_host = std::getenv("REDIS_HOST") ? std::getenv("REDIS_HOST") : "127.0.0.1";
  const std::string stream_name =
      std::getenv("REDIS_STREAM_NAME") ? std::getenv("REDIS_STREAM_NAME") : "notifications_stream";

  int server_fd = CreateServerSocket(port);
  if (server_fd < 0) {
    std::cerr << "Failed to bind gateway on port " << port << ": " << std::strerror(errno) << "\n";
    return 1;
  }

  std::cout << "notification-gateway listening on :" << port << "\n";
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

    if (req.method != "POST" || req.path != "/v1/notifications") {
      WriteHttpResponse(client_fd, 404, "Not Found", "{\"error\":\"route not found\"}");
      close(client_fd);
      continue;
    }

    auto content = ExtractJsonStringField(req.body, "content");
    if (!content.has_value() || content->empty()) {
      WriteHttpResponse(client_fd, 400, "Bad Request", "{\"error\":\"content is required\"}");
      close(client_fd);
      continue;
    }

    std::string tenant_id;
    if (auto from_token = ExtractTenantFromJwt(req.headers); from_token.has_value()) {
      tenant_id = from_token.value();
    } else if (auto from_body = ExtractJsonStringField(req.body, "tenant_id"); from_body.has_value()) {
      tenant_id = from_body.value();
    } else {
      WriteHttpResponse(client_fd, 401, "Unauthorized",
                        "{\"error\":\"tenant_id not found in JWT or payload\"}");
      close(client_fd);
      continue;
    }

    const std::string user_id =
        ExtractJsonStringField(req.body, "user_id").value_or("unknown-user");
    const std::string channel =
        ExtractJsonStringField(req.body, "channel").value_or("default");

    std::unordered_map<std::string, std::string> fields = {
        {"tenant_id", tenant_id},
        {"user_id", user_id},
        {"channel", channel},
        {"content", content.value()},
    };

    std::string redis_reply;
    if (!PublishToRedisStream(redis_host, redis_port, stream_name, fields, redis_reply)) {
      WriteHttpResponse(client_fd, 503, "Service Unavailable",
                        "{\"error\":\"failed to publish to redis stream\"}");
      close(client_fd);
      continue;
    }

    std::ostringstream response;
    response << "{\"status\":\"accepted\",\"tenant_id\":\"" << tenant_id
             << "\",\"stream\":\"" << stream_name << "\"}";
    WriteHttpResponse(client_fd, 202, "Accepted", response.str());
    close(client_fd);
  }

  close(server_fd);
  return 0;
}
