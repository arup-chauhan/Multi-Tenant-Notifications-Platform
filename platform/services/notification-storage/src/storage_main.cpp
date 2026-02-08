#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
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

std::string ParseStrEnv(const char* key, const std::string& fallback) {
  const char* value = std::getenv(key);
  return value == nullptr ? fallback : value;
}

bool ParseBoolEnv(const char* key, bool fallback) {
  const char* value = std::getenv(key);
  if (value == nullptr) {
    return fallback;
  }
  std::string v(value);
  std::transform(v.begin(), v.end(), v.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  if (v == "1" || v == "true" || v == "yes") {
    return true;
  }
  if (v == "0" || v == "false" || v == "no") {
    return false;
  }
  return fallback;
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

std::optional<std::string> ExtractJsonNumberField(const std::string& json, const std::string& key) {
  const std::string needle = "\"" + key + "\"";
  size_t k = json.find(needle);
  if (k == std::string::npos) {
    return std::nullopt;
  }
  size_t colon = json.find(':', k + needle.size());
  if (colon == std::string::npos) {
    return std::nullopt;
  }
  size_t start = colon + 1;
  while (start < json.size() && std::isspace(static_cast<unsigned char>(json[start]))) {
    ++start;
  }
  size_t end = start;
  if (end < json.size() && (json[end] == '-' || json[end] == '+')) {
    ++end;
  }
  while (end < json.size() && std::isdigit(static_cast<unsigned char>(json[end]))) {
    ++end;
  }
  if (end == start) {
    return std::nullopt;
  }
  return json.substr(start, end - start);
}

std::string EscapeForCql(const std::string& value) {
  std::string out;
  out.reserve(value.size());
  for (char c : value) {
    if (c == '\'') {
      out += "''";
    } else {
      out.push_back(c);
    }
  }
  return out;
}

bool RunCql(const std::string& cassandra_host, int cassandra_port, const std::string& cql) {
  char file_template[] = "/tmp/storage-cql-XXXXXX";
  int fd = mkstemp(file_template);
  if (fd < 0) {
    return false;
  }

  {
    std::ofstream temp(file_template);
    if (!temp.is_open()) {
      close(fd);
      std::remove(file_template);
      return false;
    }
    temp << cql;
  }
  close(fd);

  std::ostringstream cmd;
  cmd << "cqlsh " << cassandra_host << " " << cassandra_port << " -f " << file_template;
  int rc = std::system(cmd.str().c_str());
  std::remove(file_template);
  return rc == 0;
}

bool AppendRecordFile(const std::string& file_path, const std::string& payload) {
  std::ofstream out(file_path, std::ios::app);
  if (!out.is_open()) {
    return false;
  }
  std::time_t now = std::time(nullptr);
  out << "{\"ts\":" << static_cast<long long>(now) << ",\"record\":" << payload << "}\n";
  return true;
}

bool PersistRecord(const std::string& backend,
                   const std::string& storage_file,
                   bool fallback_to_file,
                   const std::string& cassandra_host,
                   int cassandra_port,
                   const std::string& cassandra_keyspace,
                   const std::string& body,
                   const std::string& tenant_id,
                   const std::string& notification_id,
                   const std::string& user_id,
                   const std::string& channel,
                   const std::string& content,
                   const std::string& status,
                   const std::string& attempt,
                   const std::string& error) {
  if (backend == "cassandra") {
    std::ostringstream cql;
    cql << "INSERT INTO " << cassandra_keyspace << ".delivery_status "
        << "(tenant_id, notification_id, status_ts, user_id, channel, content, status, attempt, error) VALUES ("
        << "'" << EscapeForCql(tenant_id) << "',"
        << "'" << EscapeForCql(notification_id) << "',"
        << "toTimestamp(now()),"
        << "'" << EscapeForCql(user_id) << "',"
        << "'" << EscapeForCql(channel) << "',"
        << "'" << EscapeForCql(content) << "',"
        << "'" << EscapeForCql(status) << "',"
        << attempt << ","
        << "'" << EscapeForCql(error) << "');\n";

    if (RunCql(cassandra_host, cassandra_port, cql.str())) {
      return true;
    }
    if (!fallback_to_file) {
      return false;
    }
  }

  return AppendRecordFile(storage_file, body);
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
  const auto cassandra_port_opt = ParseIntEnv("CASSANDRA_PORT", 9042);
  if (!port_opt.has_value() || !cassandra_port_opt.has_value()) {
    std::cerr << "invalid numeric env\n";
    return 1;
  }

  const int port = port_opt.value();
  const int cassandra_port = cassandra_port_opt.value();

  const std::string storage_file = ParseStrEnv("STORAGE_DATA_FILE", "/tmp/notification_storage.log");
  const std::string backend = ToLower(ParseStrEnv("STORAGE_BACKEND", "cassandra"));
  const bool fallback_to_file = ParseBoolEnv("STORAGE_FALLBACK_TO_FILE", true);
  const std::string cassandra_host = ParseStrEnv("CASSANDRA_HOST", "cassandra");
  const std::string cassandra_keyspace = ParseStrEnv("CASSANDRA_KEYSPACE", "notification_platform");

  int server_fd = CreateServerSocket(port);
  if (server_fd < 0) {
    std::cerr << "failed to bind storage on port " << port << ": " << std::strerror(errno) << "\n";
    return 1;
  }

  std::cout << "notification-storage listening on :" << port
            << " backend=" << backend
            << " cassandra=" << cassandra_host << ":" << cassandra_port
            << " keyspace=" << cassandra_keyspace
            << " fallback_to_file=" << (fallback_to_file ? "true" : "false") << "\n";

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
    const auto notification_id = ExtractJsonStringField(req.body, "notification_id");
    const auto user_id = ExtractJsonStringField(req.body, "user_id");
    const auto channel = ExtractJsonStringField(req.body, "channel");
    const auto content = ExtractJsonStringField(req.body, "content");
    const auto status = ExtractJsonStringField(req.body, "status");
    const auto attempt = ExtractJsonNumberField(req.body, "attempt");
    const auto error = ExtractJsonStringField(req.body, "error");

    if (!tenant.has_value() || !status.has_value() || !notification_id.has_value()) {
      WriteHttpResponse(client_fd, 400, "Bad Request",
                        "{\"error\":\"tenant_id, status and notification_id are required\"}");
      close(client_fd);
      continue;
    }

    const std::string attempt_value = attempt.value_or("0");
    if (!PersistRecord(backend, storage_file, fallback_to_file,
                       cassandra_host, cassandra_port, cassandra_keyspace,
                       req.body,
                       tenant.value(), notification_id.value(), user_id.value_or("unknown"),
                       channel.value_or("default"), content.value_or(""),
                       status.value(), attempt_value, error.value_or(""))) {
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
