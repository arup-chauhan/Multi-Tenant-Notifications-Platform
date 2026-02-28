#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <ctime>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

struct HttpRequest {
  std::string method;
  std::string path;
  std::unordered_map<std::string, std::string> headers;
  std::string body;
};

struct WebSocketClient {
  int fd = -1;
  std::string auth_tenant_id;
  std::string subscribed_tenant_id;
  std::string subscribed_channel;
};

std::mutex g_ws_clients_mu;
std::vector<std::shared_ptr<WebSocketClient>> g_ws_clients;

std::atomic<long long> g_requests_total{0};
std::atomic<long long> g_notifications_accepted_total{0};
std::atomic<long long> g_notifications_rejected_total{0};
std::atomic<long long> g_rate_limited_total{0};
std::atomic<long long> g_backpressure_rejected_total{0};
std::atomic<long long> g_notifications_delivered_total{0};
std::atomic<long long> g_correlation_seq{0};

struct TenantRateWindow {
  long long minute_epoch = 0;
  int count = 0;
};
std::mutex g_tenant_rate_mu;
std::unordered_map<std::string, TenantRateWindow> g_tenant_rate_windows;

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

std::string StripQuery(const std::string& path) {
  size_t q = path.find('?');
  if (q == std::string::npos) {
    return path;
  }
  return path.substr(0, q);
}

std::optional<std::string> PathQueryParam(const std::string& path, const std::string& key) {
  size_t q = path.find('?');
  if (q == std::string::npos || q + 1 >= path.size()) {
    return std::nullopt;
  }
  const std::string query = path.substr(q + 1);
  size_t start = 0;
  while (start < query.size()) {
    size_t amp = query.find('&', start);
    if (amp == std::string::npos) {
      amp = query.size();
    }
    const std::string pair = query.substr(start, amp - start);
    size_t eq = pair.find('=');
    if (eq != std::string::npos && pair.substr(0, eq) == key) {
      return pair.substr(eq + 1);
    }
    start = amp + 1;
  }
  return std::nullopt;
}

std::optional<std::string> PathSuffix(const std::string& path, const std::string& prefix) {
  const std::string stripped = StripQuery(path);
  if (stripped.rfind(prefix, 0) != 0 || stripped.size() <= prefix.size()) {
    return std::nullopt;
  }
  return stripped.substr(prefix.size());
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

bool ParseBoolEnv(const char* key, bool fallback) {
  const char* value = std::getenv(key);
  if (value == nullptr) {
    return fallback;
  }
  std::string v = ToLower(value);
  if (v == "1" || v == "true" || v == "yes") {
    return true;
  }
  if (v == "0" || v == "false" || v == "no") {
    return false;
  }
  return fallback;
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

std::optional<long long> ExtractJsonIntegerField(const std::string& json,
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
  size_t start = colon + 1;
  while (start < json.size() && std::isspace(static_cast<unsigned char>(json[start]))) {
    ++start;
  }
  if (start >= json.size()) {
    return std::nullopt;
  }

  size_t end = start;
  if (json[end] == '-' || json[end] == '+') {
    ++end;
  }
  while (end < json.size() && std::isdigit(static_cast<unsigned char>(json[end]))) {
    ++end;
  }
  if (end == start || (end == start + 1 && (json[start] == '-' || json[start] == '+'))) {
    return std::nullopt;
  }
  try {
    return std::stoll(json.substr(start, end - start));
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<bool> ExtractJsonBoolField(const std::string& json,
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
  size_t start = colon + 1;
  while (start < json.size() && std::isspace(static_cast<unsigned char>(json[start]))) {
    ++start;
  }
  if (json.compare(start, 4, "true") == 0) {
    return true;
  }
  if (json.compare(start, 5, "false") == 0) {
    return false;
  }
  return std::nullopt;
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

struct JwtTenantResult {
  enum class Status { kNoToken, kValid, kInvalid };
  Status status = Status::kNoToken;
  std::optional<std::string> tenant_id;
  std::string error;
};

bool IsAlgHs256(const std::string& header_json) {
  auto alg = ExtractJsonStringField(header_json, "alg");
  return alg.has_value() && alg.value() == "HS256";
}

bool VerifyJwtHs256Signature(const std::string& signing_input, const std::string& signature_b64url,
                             const std::string& secret) {
  if (secret.empty()) {
    return false;
  }
  auto expected_sig = Base64UrlDecode(signature_b64url);
  if (!expected_sig.has_value()) {
    return false;
  }

  unsigned int digest_len = 0;
  unsigned char digest[EVP_MAX_MD_SIZE];
  const unsigned char* hmac = HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()),
                                   reinterpret_cast<const unsigned char*>(signing_input.data()),
                                   signing_input.size(), digest, &digest_len);
  if (hmac == nullptr || digest_len != expected_sig->size()) {
    return false;
  }
  return CRYPTO_memcmp(digest, expected_sig->data(), digest_len) == 0;
}

JwtTenantResult ExtractTenantFromJwt(const std::unordered_map<std::string, std::string>& headers,
                                     const std::string& jwt_hs256_secret,
                                     long long jwt_clock_skew_seconds) {
  auto token = ExtractBearerToken(headers);
  if (!token.has_value()) {
    return JwtTenantResult{};
  }

  size_t first_dot = token->find('.');
  if (first_dot == std::string::npos || first_dot == 0) {
    return JwtTenantResult{JwtTenantResult::Status::kInvalid, std::nullopt,
                           "invalid JWT format"};
  }
  size_t second_dot = token->find('.', first_dot + 1);
  if (second_dot == std::string::npos || second_dot <= first_dot + 1 ||
      second_dot + 1 >= token->size()) {
    return JwtTenantResult{JwtTenantResult::Status::kInvalid, std::nullopt,
                           "invalid JWT format"};
  }

  const std::string header_segment = token->substr(0, first_dot);
  const std::string payload_segment = token->substr(first_dot + 1, second_dot - first_dot - 1);
  const std::string signature_segment = token->substr(second_dot + 1);

  auto header = Base64UrlDecode(header_segment);
  if (!header.has_value() || !IsAlgHs256(header.value())) {
    return JwtTenantResult{JwtTenantResult::Status::kInvalid, std::nullopt,
                           "unsupported JWT alg"};
  }

  const std::string signing_input = header_segment + "." + payload_segment;
  if (!VerifyJwtHs256Signature(signing_input, signature_segment, jwt_hs256_secret)) {
    return JwtTenantResult{JwtTenantResult::Status::kInvalid, std::nullopt,
                           "invalid JWT signature"};
  }

  auto payload = Base64UrlDecode(payload_segment);
  if (!payload.has_value()) {
    return JwtTenantResult{JwtTenantResult::Status::kInvalid, std::nullopt,
                           "invalid JWT payload"};
  }
  const std::string& payload_json = payload.value();

  const auto exp = ExtractJsonIntegerField(payload_json, "exp");
  if (!exp.has_value()) {
    return JwtTenantResult{JwtTenantResult::Status::kInvalid, std::nullopt,
                           "missing exp claim"};
  }
  const long long now = static_cast<long long>(std::time(nullptr));
  if (now > exp.value() + jwt_clock_skew_seconds) {
    return JwtTenantResult{JwtTenantResult::Status::kInvalid, std::nullopt,
                           "token expired"};
  }

  const auto nbf = ExtractJsonIntegerField(payload_json, "nbf");
  if (nbf.has_value() && now + jwt_clock_skew_seconds < nbf.value()) {
    return JwtTenantResult{JwtTenantResult::Status::kInvalid, std::nullopt,
                           "token not yet valid"};
  }

  const auto iat = ExtractJsonIntegerField(payload_json, "iat");
  if (iat.has_value() && now + jwt_clock_skew_seconds < iat.value()) {
    return JwtTenantResult{JwtTenantResult::Status::kInvalid, std::nullopt,
                           "token issued in the future"};
  }

  auto tenant = ExtractJsonStringField(payload_json, "tenant_id");
  if (tenant.has_value()) {
    return JwtTenantResult{JwtTenantResult::Status::kValid, tenant, ""};
  }
  tenant = ExtractJsonStringField(payload_json, "tid");
  if (tenant.has_value()) {
    return JwtTenantResult{JwtTenantResult::Status::kValid, tenant, ""};
  }
  return JwtTenantResult{JwtTenantResult::Status::kInvalid, std::nullopt,
                         "tenant claim missing in JWT"};
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

std::string JsonEscape(const std::string& input) {
  std::string out;
  out.reserve(input.size() + 16);
  for (char c : input) {
    switch (c) {
      case '\\':
        out += "\\\\";
        break;
      case '"':
        out += "\\\"";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        out.push_back(c);
    }
  }
  return out;
}

void LogJsonEvent(const std::string& event, const std::string& outcome,
                  const std::string& tenant_id, const std::string& correlation_id = "",
                  const std::string& detail = "") {
  std::ostringstream line;
  line << "{\"ts\":" << static_cast<long long>(std::time(nullptr))
       << ",\"service\":\"gateway\""
       << ",\"event\":\"" << JsonEscape(event) << "\""
       << ",\"outcome\":\"" << JsonEscape(outcome) << "\""
       << ",\"tenant_id\":\"" << JsonEscape(tenant_id) << "\"";
  if (!correlation_id.empty()) {
    line << ",\"correlation_id\":\"" << JsonEscape(correlation_id) << "\"";
  }
  if (!detail.empty()) {
    line << ",\"detail\":\"" << JsonEscape(detail) << "\"";
  }
  line << "}";
  std::cout << line.str() << "\n";
}

std::string GenerateCorrelationId() {
  std::ostringstream out;
  out << "corr-" << static_cast<long long>(std::time(nullptr)) << "-"
      << g_correlation_seq.fetch_add(1);
  return out.str();
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

int ConnectTcp(const std::string& host, int port) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  addrinfo* result = nullptr;
  if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &result) != 0) {
    return -1;
  }

  int fd = -1;
  for (addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd < 0) {
      continue;
    }
    if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
      break;
    }
    close(fd);
    fd = -1;
  }
  freeaddrinfo(result);
  return fd;
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
  int redis_fd = ConnectTcp(host, port);
  if (redis_fd < 0) {
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

std::optional<long long> ParseRedisIntegerReply(const std::string& reply) {
  if (reply.empty() || reply[0] != ':') {
    return std::nullopt;
  }
  try {
    return std::stoll(reply.substr(1));
  } catch (...) {
    return std::nullopt;
  }
}

bool ExceedsTenantDailyQuota(const std::string& redis_host, int redis_port,
                             const std::string& tenant_id, int daily_quota,
                             bool& out_exceeded, long long& out_current) {
  out_exceeded = false;
  out_current = 0;
  if (daily_quota <= 0) {
    return true;
  }

  const long long day_epoch = static_cast<long long>(std::time(nullptr) / 86400);
  const std::string key = "quota:tenant:" + tenant_id + ":" + std::to_string(day_epoch);

  int redis_fd = ConnectTcp(redis_host, redis_port);
  if (redis_fd < 0) {
    return false;
  }

  std::string incr_reply;
  if (!SendAll(redis_fd, RedisRespArray({"INCR", key})) ||
      !ReadRedisSimpleReply(redis_fd, incr_reply)) {
    close(redis_fd);
    return false;
  }
  const auto current = ParseRedisIntegerReply(incr_reply);
  if (!current.has_value()) {
    close(redis_fd);
    return false;
  }
  out_current = current.value();

  if (current.value() == 1) {
    std::string expire_reply;
    // Expire in 2 days to avoid stale key buildup while preserving daily buckets.
    SendAll(redis_fd, RedisRespArray({"EXPIRE", key, "172800"}));
    ReadRedisSimpleReply(redis_fd, expire_reply);
  }
  close(redis_fd);

  out_exceeded = current.value() > daily_quota;
  return true;
}

bool GetRedisStreamLength(const std::string& redis_host, int redis_port, const std::string& stream,
                          long long& out_length) {
  out_length = 0;
  int redis_fd = ConnectTcp(redis_host, redis_port);
  if (redis_fd < 0) {
    return false;
  }
  std::string reply;
  if (!SendAll(redis_fd, RedisRespArray({"XLEN", stream})) ||
      !ReadRedisSimpleReply(redis_fd, reply)) {
    close(redis_fd);
    return false;
  }
  close(redis_fd);
  const auto value = ParseRedisIntegerReply(reply);
  if (!value.has_value()) {
    return false;
  }
  out_length = value.value();
  return true;
}

bool HttpGet(const std::string& host, int port, const std::string& path, int& status_code,
             std::string& response_body) {
  int fd = ConnectTcp(host, port);
  if (fd < 0) {
    return false;
  }

  std::ostringstream req;
  req << "GET " << path << " HTTP/1.1\r\n";
  req << "Host: " << host << ":" << port << "\r\n";
  req << "Connection: close\r\n\r\n";
  if (!SendAll(fd, req.str())) {
    close(fd);
    return false;
  }

  std::string response;
  char buf[1024];
  while (true) {
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) {
      break;
    }
    response.append(buf, static_cast<size_t>(n));
    if (response.size() > 2 * 1024 * 1024) {
      break;
    }
  }
  close(fd);

  const size_t status_end = response.find("\r\n");
  if (status_end == std::string::npos) {
    return false;
  }
  std::istringstream status_stream(response.substr(0, status_end));
  std::string http_version;
  if (!(status_stream >> http_version >> status_code)) {
    return false;
  }
  const size_t body_pos = response.find("\r\n\r\n");
  response_body = (body_pos == std::string::npos) ? "" : response.substr(body_pos + 4);
  return true;
}

bool HttpPostJson(const std::string& host, int port, const std::string& path,
                  const std::string& body, int& status_code, std::string& response_body) {
  int fd = ConnectTcp(host, port);
  if (fd < 0) {
    return false;
  }

  std::ostringstream req;
  req << "POST " << path << " HTTP/1.1\r\n";
  req << "Host: " << host << ":" << port << "\r\n";
  req << "Content-Type: application/json\r\n";
  req << "Content-Length: " << body.size() << "\r\n";
  req << "Connection: close\r\n\r\n";
  req << body;
  if (!SendAll(fd, req.str())) {
    close(fd);
    return false;
  }

  std::string response;
  char buf[1024];
  while (true) {
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) {
      break;
    }
    response.append(buf, static_cast<size_t>(n));
    if (response.size() > 2 * 1024 * 1024) {
      break;
    }
  }
  close(fd);

  const size_t status_end = response.find("\r\n");
  if (status_end == std::string::npos) {
    return false;
  }
  std::istringstream status_stream(response.substr(0, status_end));
  std::string http_version;
  if (!(status_stream >> http_version >> status_code)) {
    return false;
  }
  const size_t body_pos = response.find("\r\n\r\n");
  response_body = (body_pos == std::string::npos) ? "" : response.substr(body_pos + 4);
  return true;
}

struct IdempotencyClaimResult {
  bool ok = false;
  bool claimed = false;
  std::string notification_id;
};

IdempotencyClaimResult ClaimIdempotency(const std::string& storage_host, int storage_port,
                                        const std::string& tenant_id,
                                        const std::string& idempotency_key,
                                        const std::string& notification_id) {
  IdempotencyClaimResult out{};
  std::ostringstream body;
  body << "{\"tenant_id\":\"" << JsonEscape(tenant_id) << "\","
       << "\"idempotency_key\":\"" << JsonEscape(idempotency_key) << "\","
       << "\"notification_id\":\"" << JsonEscape(notification_id) << "\"}";

  int status = 0;
  std::string response_body;
  if (!HttpPostJson(storage_host, storage_port, "/v1/internal/idempotency/claim",
                    body.str(), status, response_body)) {
    return out;
  }
  if (status < 200 || status >= 300) {
    return out;
  }

  const auto claimed = ExtractJsonBoolField(response_body, "claimed");
  if (!claimed.has_value()) {
    return out;
  }

  out.ok = true;
  out.claimed = claimed.value();
  out.notification_id = ExtractJsonStringField(response_body, "notification_id").value_or("");
  return out;
}

bool ReleaseIdempotency(const std::string& storage_host, int storage_port,
                        const std::string& tenant_id, const std::string& idempotency_key,
                        const std::string& notification_id) {
  std::ostringstream body;
  body << "{\"tenant_id\":\"" << JsonEscape(tenant_id) << "\","
       << "\"idempotency_key\":\"" << JsonEscape(idempotency_key) << "\","
       << "\"notification_id\":\"" << JsonEscape(notification_id) << "\"}";

  int status = 0;
  std::string response_body;
  if (!HttpPostJson(storage_host, storage_port, "/v1/internal/idempotency/release",
                    body.str(), status, response_body)) {
    return false;
  }
  if (status < 200 || status >= 300) {
    return false;
  }
  const auto released = ExtractJsonBoolField(response_body, "released");
  return released.value_or(false);
}

bool IsRateLimited(const std::string& tenant_id, int per_minute_limit) {
  if (per_minute_limit <= 0) {
    return false;
  }
  const long long minute = static_cast<long long>(std::time(nullptr) / 60);
  std::lock_guard<std::mutex> lock(g_tenant_rate_mu);
  auto& window = g_tenant_rate_windows[tenant_id];
  if (window.minute_epoch != minute) {
    window.minute_epoch = minute;
    window.count = 0;
  }
  if (window.count >= per_minute_limit) {
    return true;
  }
  ++window.count;
  return false;
}

int ActiveWsSessions() {
  std::lock_guard<std::mutex> lock(g_ws_clients_mu);
  int active = 0;
  for (const auto& client : g_ws_clients) {
    if (client->fd >= 0) {
      ++active;
    }
  }
  return active;
}

std::string BuildPrometheusMetrics() {
  std::ostringstream out;
  out << "# TYPE gateway_requests_total counter\n";
  out << "gateway_requests_total " << g_requests_total.load() << "\n";
  out << "# TYPE notifications_accepted_total counter\n";
  out << "notifications_accepted_total " << g_notifications_accepted_total.load() << "\n";
  out << "# TYPE notifications_ingested_total counter\n";
  out << "notifications_ingested_total " << g_notifications_accepted_total.load() << "\n";
  out << "# TYPE notifications_rejected_total counter\n";
  out << "notifications_rejected_total " << g_notifications_rejected_total.load() << "\n";
  out << "# TYPE notifications_rate_limited_total counter\n";
  out << "notifications_rate_limited_total " << g_rate_limited_total.load() << "\n";
  out << "# TYPE notifications_backpressure_rejected_total counter\n";
  out << "notifications_backpressure_rejected_total " << g_backpressure_rejected_total.load()
      << "\n";
  out << "# TYPE notifications_delivered_total counter\n";
  out << "notifications_delivered_total " << g_notifications_delivered_total.load() << "\n";
  out << "# TYPE websocket_active_sessions gauge\n";
  out << "websocket_active_sessions " << ActiveWsSessions() << "\n";
  return out.str();
}

// SHA1 and base64 are used to complete RFC6455 websocket handshake.
std::array<uint8_t, 20> Sha1(const std::string& input) {
  uint64_t ml = static_cast<uint64_t>(input.size()) * 8;
  std::vector<uint8_t> data(input.begin(), input.end());
  data.push_back(0x80);
  while ((data.size() % 64) != 56) {
    data.push_back(0x00);
  }
  for (int i = 7; i >= 0; --i) {
    data.push_back(static_cast<uint8_t>((ml >> (i * 8)) & 0xFF));
  }

  uint32_t h0 = 0x67452301;
  uint32_t h1 = 0xEFCDAB89;
  uint32_t h2 = 0x98BADCFE;
  uint32_t h3 = 0x10325476;
  uint32_t h4 = 0xC3D2E1F0;

  auto rol = [](uint32_t v, int n) { return (v << n) | (v >> (32 - n)); };

  for (size_t chunk = 0; chunk < data.size(); chunk += 64) {
    uint32_t w[80] = {0};
    for (int i = 0; i < 16; ++i) {
      size_t j = chunk + i * 4;
      w[i] = (static_cast<uint32_t>(data[j]) << 24) |
             (static_cast<uint32_t>(data[j + 1]) << 16) |
             (static_cast<uint32_t>(data[j + 2]) << 8) |
             (static_cast<uint32_t>(data[j + 3]));
    }
    for (int i = 16; i < 80; ++i) {
      w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
    for (int i = 0; i < 80; ++i) {
      uint32_t f = 0;
      uint32_t k = 0;
      if (i < 20) {
        f = (b & c) | ((~b) & d);
        k = 0x5A827999;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDC;
      } else {
        f = b ^ c ^ d;
        k = 0xCA62C1D6;
      }
      uint32_t temp = rol(a, 5) + f + e + k + w[i];
      e = d;
      d = c;
      c = rol(b, 30);
      b = a;
      a = temp;
    }

    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
  }

  std::array<uint8_t, 20> out{};
  auto write_word = [&](uint32_t word, int offset) {
    out[offset] = static_cast<uint8_t>((word >> 24) & 0xFF);
    out[offset + 1] = static_cast<uint8_t>((word >> 16) & 0xFF);
    out[offset + 2] = static_cast<uint8_t>((word >> 8) & 0xFF);
    out[offset + 3] = static_cast<uint8_t>(word & 0xFF);
  };
  write_word(h0, 0);
  write_word(h1, 4);
  write_word(h2, 8);
  write_word(h3, 12);
  write_word(h4, 16);
  return out;
}

std::string Base64Encode(const uint8_t* data, size_t len) {
  static const char table[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((len + 2) / 3) * 4);
  for (size_t i = 0; i < len; i += 3) {
    uint32_t n = static_cast<uint32_t>(data[i]) << 16;
    bool have2 = i + 1 < len;
    bool have3 = i + 2 < len;
    if (have2) n |= static_cast<uint32_t>(data[i + 1]) << 8;
    if (have3) n |= static_cast<uint32_t>(data[i + 2]);

    out.push_back(table[(n >> 18) & 0x3F]);
    out.push_back(table[(n >> 12) & 0x3F]);
    out.push_back(have2 ? table[(n >> 6) & 0x3F] : '=');
    out.push_back(have3 ? table[n & 0x3F] : '=');
  }
  return out;
}

bool SendWebSocketFrame(int fd, uint8_t opcode, const std::string& payload) {
  std::string frame;
  frame.push_back(static_cast<char>(0x80 | (opcode & 0x0F)));

  const uint64_t len = payload.size();
  if (len <= 125) {
    frame.push_back(static_cast<char>(len));
  } else if (len <= 0xFFFF) {
    frame.push_back(static_cast<char>(126));
    frame.push_back(static_cast<char>((len >> 8) & 0xFF));
    frame.push_back(static_cast<char>(len & 0xFF));
  } else {
    frame.push_back(static_cast<char>(127));
    for (int i = 7; i >= 0; --i) {
      frame.push_back(static_cast<char>((len >> (i * 8)) & 0xFF));
    }
  }
  frame += payload;
  return SendAll(fd, frame);
}

bool ReadWebSocketFrame(int fd, uint8_t& opcode, std::string& payload) {
  std::string head;
  if (!ReadExact(fd, head, 2)) {
    return false;
  }

  opcode = static_cast<uint8_t>(head[0]) & 0x0F;
  bool masked = (static_cast<uint8_t>(head[1]) & 0x80) != 0;
  uint64_t len = static_cast<uint8_t>(head[1]) & 0x7F;

  if (len == 126) {
    std::string ext;
    if (!ReadExact(fd, ext, 2)) {
      return false;
    }
    len = (static_cast<uint8_t>(ext[0]) << 8) | static_cast<uint8_t>(ext[1]);
  } else if (len == 127) {
    std::string ext;
    if (!ReadExact(fd, ext, 8)) {
      return false;
    }
    len = 0;
    for (int i = 0; i < 8; ++i) {
      len = (len << 8) | static_cast<uint8_t>(ext[i]);
    }
  }

  if (len > 1024 * 1024) {
    return false;
  }

  std::array<uint8_t, 4> mask = {0, 0, 0, 0};
  if (masked) {
    std::string mask_bytes;
    if (!ReadExact(fd, mask_bytes, 4)) {
      return false;
    }
    for (int i = 0; i < 4; ++i) {
      mask[i] = static_cast<uint8_t>(mask_bytes[i]);
    }
  }

  if (!ReadExact(fd, payload, static_cast<size_t>(len))) {
    return false;
  }

  if (masked) {
    for (size_t i = 0; i < payload.size(); ++i) {
      payload[i] = static_cast<char>(static_cast<uint8_t>(payload[i]) ^ mask[i % 4]);
    }
  }
  return true;
}

std::shared_ptr<WebSocketClient> AddWebSocketClient(int fd) {
  auto client = std::make_shared<WebSocketClient>();
  client->fd = fd;
  std::lock_guard<std::mutex> lock(g_ws_clients_mu);
  g_ws_clients.push_back(client);
  return client;
}

void SetWebSocketAuthTenant(int fd, const std::string& tenant_id) {
  std::lock_guard<std::mutex> lock(g_ws_clients_mu);
  for (auto& client : g_ws_clients) {
    if (client->fd == fd) {
      client->auth_tenant_id = tenant_id;
      return;
    }
  }
}

bool SetWebSocketSubscription(int fd, const std::string& tenant_id, const std::string& channel) {
  std::lock_guard<std::mutex> lock(g_ws_clients_mu);
  for (auto& client : g_ws_clients) {
    if (client->fd == fd) {
      client->subscribed_tenant_id = tenant_id;
      client->subscribed_channel = channel;
      return true;
    }
  }
  return false;
}

void RemoveWebSocketClient(int fd) {
  std::lock_guard<std::mutex> lock(g_ws_clients_mu);
  g_ws_clients.erase(
      std::remove_if(g_ws_clients.begin(), g_ws_clients.end(),
                     [&](const std::shared_ptr<WebSocketClient>& c) { return c->fd == fd; }),
      g_ws_clients.end());
}

int BroadcastToWebSockets(const std::string& message, const std::string& tenant_id,
                          const std::string& channel) {
  std::vector<int> targets;
  {
    std::lock_guard<std::mutex> lock(g_ws_clients_mu);
    for (const auto& client : g_ws_clients) {
      if (client->fd < 0) {
        continue;
      }
      if (client->subscribed_tenant_id != tenant_id || client->subscribed_channel != channel) {
        continue;
      }
      targets.push_back(client->fd);
    }
  }

  int delivered = 0;
  for (int client_fd : targets) {
    if (SendWebSocketFrame(client_fd, 0x1, message)) {
      ++delivered;
      continue;
    }
    RemoveWebSocketClient(client_fd);
    close(client_fd);
  }
  return delivered;
}

bool HandleWebSocketUpgrade(int client_fd, const HttpRequest& req,
                            const std::optional<std::string>& auth_tenant_id) {
  auto key_it = req.headers.find("sec-websocket-key");
  if (key_it == req.headers.end() || key_it->second.empty()) {
    return false;
  }

  const std::string accept_seed = key_it->second + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  const auto digest = Sha1(accept_seed);
  const std::string accept = Base64Encode(digest.data(), digest.size());

  std::ostringstream response;
  response << "HTTP/1.1 101 Switching Protocols\r\n";
  response << "Upgrade: websocket\r\n";
  response << "Connection: Upgrade\r\n";
  response << "Sec-WebSocket-Accept: " << accept << "\r\n\r\n";

  if (!SendAll(client_fd, response.str())) {
    return false;
  }

  auto ws_client = AddWebSocketClient(client_fd);
  if (auth_tenant_id.has_value()) {
    SetWebSocketAuthTenant(client_fd, auth_tenant_id.value());
  }

  while (true) {
    uint8_t opcode = 0;
    std::string payload;
    if (!ReadWebSocketFrame(client_fd, opcode, payload)) {
      break;
    }
    if (opcode == 0x8) {  // close
      SendWebSocketFrame(client_fd, 0x8, "");
      break;
    }
    if (opcode == 0x9) {  // ping
      SendWebSocketFrame(client_fd, 0xA, payload);
      continue;
    }
    if (opcode == 0x1) {  // text
      auto type = ExtractJsonStringField(payload, "type");
      if (!type.has_value() || type.value() != "subscribe") {
        continue;
      }

      auto tenant = ExtractJsonStringField(payload, "tenant_id");
      auto channel = ExtractJsonStringField(payload, "channel");
      if (!tenant.has_value() || !channel.has_value() || tenant->empty() || channel->empty()) {
        continue;
      }
      if (!ws_client->auth_tenant_id.empty() && ws_client->auth_tenant_id != tenant.value()) {
        SendWebSocketFrame(client_fd, 0x8, "");
        break;
      }
      SetWebSocketSubscription(client_fd, tenant.value(), channel.value());
    }
  }

  RemoveWebSocketClient(client_fd);
  close(client_fd);
  ws_client->fd = -1;
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

void HandleClientConnection(int client_fd, const std::string redis_host, const int redis_port,
                            const std::string stream_name,
                            const std::string retry_stream_name,
                            const std::string storage_host,
                            int storage_port,
                            const std::string jwt_hs256_secret,
                            bool gateway_require_auth,
                            long long jwt_clock_skew_seconds,
                            int tenant_rate_limit_per_minute,
                            int tenant_daily_quota,
                            int max_stream_backlog,
                            int max_retry_stream_backlog) {
  g_requests_total.fetch_add(1);
  HttpRequest req;
  if (!ReadHttpRequest(client_fd, req)) {
    g_notifications_rejected_total.fetch_add(1);
    WriteHttpResponse(client_fd, 400, "Bad Request", "{\"error\":\"invalid request\"}");
    close(client_fd);
    return;
  }

  const std::string path = StripQuery(req.path);

  if (req.method == "GET" && path == "/health") {
    WriteHttpResponse(client_fd, 200, "OK", "{\"status\":\"ok\"}");
    close(client_fd);
    return;
  }

  if (req.method == "GET" && path == "/metrics") {
    const std::string body = BuildPrometheusMetrics();
    std::ostringstream response;
    response << "HTTP/1.1 200 OK\r\n";
    response << "Content-Type: text/plain; version=0.0.4\r\n";
    response << "Content-Length: " << body.size() << "\r\n";
    response << "Connection: close\r\n\r\n";
    response << body;
    SendAll(client_fd, response.str());
    close(client_fd);
    return;
  }

  if (req.method == "GET" && path == "/ws") {
    auto ws_headers = req.headers;
    if (ws_headers.find("authorization") == ws_headers.end()) {
      if (auto token = PathQueryParam(req.path, "access_token"); token.has_value() &&
                                                              !token->empty()) {
        ws_headers["authorization"] = "Bearer " + token.value();
      }
    }
    const JwtTenantResult ws_jwt =
        ExtractTenantFromJwt(ws_headers, jwt_hs256_secret, jwt_clock_skew_seconds);
    if (ws_jwt.status == JwtTenantResult::Status::kInvalid) {
      WriteHttpResponse(client_fd, 401, "Unauthorized",
                        "{\"error\":\"invalid bearer token\"}");
      close(client_fd);
      return;
    }
    if (gateway_require_auth && ws_jwt.status != JwtTenantResult::Status::kValid) {
      WriteHttpResponse(client_fd, 401, "Unauthorized",
                        "{\"error\":\"bearer token required\"}");
      close(client_fd);
      return;
    }
    std::optional<std::string> auth_tenant_id = ws_jwt.tenant_id;
    if (!HandleWebSocketUpgrade(client_fd, req, auth_tenant_id)) {
      WriteHttpResponse(client_fd, 400, "Bad Request",
                        "{\"error\":\"invalid websocket upgrade\"}");
      close(client_fd);
    }
    return;
  }

  if (req.method == "GET") {
    if (auto notification_id = PathSuffix(req.path, "/v1/notifications/"); notification_id.has_value()) {
      auto tenant_id = PathQueryParam(req.path, "tenant_id");
      if (!tenant_id.has_value() || tenant_id->empty()) {
        WriteHttpResponse(client_fd, 400, "Bad Request", "{\"error\":\"tenant_id query param is required\"}");
        close(client_fd);
        return;
      }
      const JwtTenantResult jwt_result =
          ExtractTenantFromJwt(req.headers, jwt_hs256_secret, jwt_clock_skew_seconds);
      if (jwt_result.status == JwtTenantResult::Status::kInvalid) {
        WriteHttpResponse(client_fd, 401, "Unauthorized",
                          "{\"error\":\"invalid bearer token\"}");
        close(client_fd);
        return;
      }
      if (gateway_require_auth && jwt_result.status != JwtTenantResult::Status::kValid) {
        WriteHttpResponse(client_fd, 401, "Unauthorized",
                          "{\"error\":\"bearer token required\"}");
        close(client_fd);
        return;
      }
      if (jwt_result.status == JwtTenantResult::Status::kValid && jwt_result.tenant_id.has_value() &&
          jwt_result.tenant_id.value() != tenant_id.value()) {
        WriteHttpResponse(client_fd, 403, "Forbidden",
                          "{\"error\":\"tenant access denied\"}");
        close(client_fd);
        return;
      }
      int status = 0;
      std::string body;
      const std::string storage_path =
          "/v1/internal/notifications/" + notification_id.value() + "?tenant_id=" + tenant_id.value();
      if (!HttpGet(storage_host, storage_port, storage_path, status, body)) {
        g_notifications_rejected_total.fetch_add(1);
        WriteHttpResponse(client_fd, 503, "Service Unavailable",
                          "{\"error\":\"failed to query storage\"}");
        close(client_fd);
        return;
      }
      WriteHttpResponse(client_fd, status, status == 200 ? "OK" : "Not Found",
                        body.empty() ? "{\"error\":\"not found\"}" : body);
      close(client_fd);
      return;
    }

    if (auto tenant_id = PathSuffix(req.path, "/v1/tenants/"); tenant_id.has_value()) {
      const std::string suffix = "/deliveries";
      const std::string tenant_path = tenant_id.value();
      if (tenant_path.size() > suffix.size() &&
          tenant_path.substr(tenant_path.size() - suffix.size()) == suffix) {
        const std::string tenant =
            tenant_path.substr(0, tenant_path.size() - suffix.size());
        const JwtTenantResult jwt_result =
            ExtractTenantFromJwt(req.headers, jwt_hs256_secret, jwt_clock_skew_seconds);
        if (jwt_result.status == JwtTenantResult::Status::kInvalid) {
          WriteHttpResponse(client_fd, 401, "Unauthorized",
                            "{\"error\":\"invalid bearer token\"}");
          close(client_fd);
          return;
        }
        if (gateway_require_auth && jwt_result.status != JwtTenantResult::Status::kValid) {
          WriteHttpResponse(client_fd, 401, "Unauthorized",
                            "{\"error\":\"bearer token required\"}");
          close(client_fd);
          return;
        }
        if (jwt_result.status == JwtTenantResult::Status::kValid && jwt_result.tenant_id.has_value() &&
            jwt_result.tenant_id.value() != tenant) {
          WriteHttpResponse(client_fd, 403, "Forbidden",
                            "{\"error\":\"tenant access denied\"}");
          close(client_fd);
          return;
        }
        const std::string limit = PathQueryParam(req.path, "limit").value_or("50");
        int status = 0;
        std::string body;
        const std::string storage_path =
            "/v1/internal/tenants/" + tenant + "/deliveries?limit=" + limit;
        if (!HttpGet(storage_host, storage_port, storage_path, status, body)) {
          WriteHttpResponse(client_fd, 503, "Service Unavailable",
                            "{\"error\":\"failed to query storage\"}");
          close(client_fd);
          return;
        }
        WriteHttpResponse(client_fd, status, status == 200 ? "OK" : "Not Found",
                          body.empty() ? "{\"error\":\"not found\"}" : body);
        close(client_fd);
        return;
      }
    }
  }

  if (req.method == "POST" && path == "/v1/internal/deliver") {
    if (req.body.empty()) {
      WriteHttpResponse(client_fd, 400, "Bad Request", "{\"error\":\"body is required\"}");
      close(client_fd);
      return;
    }
    const std::string tenant_id = ExtractJsonStringField(req.body, "tenant_id").value_or("");
    const std::string channel = ExtractJsonStringField(req.body, "channel").value_or("");
    std::string correlation_id = ExtractJsonStringField(req.body, "correlation_id").value_or("");
    if (correlation_id.empty()) {
      auto it = req.headers.find("x-correlation-id");
      if (it != req.headers.end()) {
        correlation_id = it->second;
      }
    }
    const int delivered = BroadcastToWebSockets(req.body, tenant_id, channel);
    g_notifications_delivered_total.fetch_add(delivered);
    LogJsonEvent("notification_delivered", "ok", tenant_id, correlation_id,
                 "clients=" + std::to_string(delivered));
    std::ostringstream body;
    body << "{\"status\":\"broadcasted\",\"clients\":" << delivered << "}";
    WriteHttpResponse(client_fd, 202, "Accepted", body.str());
    close(client_fd);
    return;
  }

  if (req.method != "POST" || path != "/v1/notifications") {
    WriteHttpResponse(client_fd, 404, "Not Found", "{\"error\":\"route not found\"}");
    close(client_fd);
    return;
  }

  auto content = ExtractJsonStringField(req.body, "content");
  if (!content.has_value() || content->empty()) {
    WriteHttpResponse(client_fd, 400, "Bad Request", "{\"error\":\"content is required\"}");
    close(client_fd);
    return;
  }

  std::string tenant_id;
  const JwtTenantResult jwt_result =
      ExtractTenantFromJwt(req.headers, jwt_hs256_secret, jwt_clock_skew_seconds);
  if (jwt_result.status == JwtTenantResult::Status::kValid && jwt_result.tenant_id.has_value()) {
    tenant_id = jwt_result.tenant_id.value();
  } else if (jwt_result.status == JwtTenantResult::Status::kInvalid) {
    WriteHttpResponse(client_fd, 401, "Unauthorized",
                      "{\"error\":\"invalid bearer token\"}");
    close(client_fd);
    return;
  } else if (gateway_require_auth) {
    WriteHttpResponse(client_fd, 401, "Unauthorized",
                      "{\"error\":\"bearer token required\"}");
    close(client_fd);
    return;
  } else if (auto from_body = ExtractJsonStringField(req.body, "tenant_id"); from_body.has_value()) {
    tenant_id = from_body.value();
  } else {
    WriteHttpResponse(client_fd, 401, "Unauthorized",
                      "{\"error\":\"tenant_id not found in JWT or payload\"}");
    close(client_fd);
    return;
  }

  if (IsRateLimited(tenant_id, tenant_rate_limit_per_minute)) {
    g_rate_limited_total.fetch_add(1);
    g_notifications_rejected_total.fetch_add(1);
    LogJsonEvent("notification_rejected", "rate_limited", tenant_id);
    WriteHttpResponse(client_fd, 429, "Too Many Requests",
                      "{\"error\":\"tenant rate limit exceeded\"}");
    close(client_fd);
    return;
  }

  bool daily_quota_exceeded = false;
  long long daily_quota_current = 0;
  if (!ExceedsTenantDailyQuota(redis_host, redis_port, tenant_id, tenant_daily_quota,
                               daily_quota_exceeded, daily_quota_current)) {
    g_notifications_rejected_total.fetch_add(1);
    LogJsonEvent("notification_rejected", "quota_check_failed", tenant_id);
    WriteHttpResponse(client_fd, 503, "Service Unavailable",
                      "{\"error\":\"failed to validate tenant quota\"}");
    close(client_fd);
    return;
  }
  if (daily_quota_exceeded) {
    g_notifications_rejected_total.fetch_add(1);
    LogJsonEvent("notification_rejected", "daily_quota_exceeded", tenant_id, "",
                 "quota_count=" + std::to_string(daily_quota_current));
    WriteHttpResponse(client_fd, 429, "Too Many Requests",
                      "{\"error\":\"tenant daily quota exceeded\"}");
    close(client_fd);
    return;
  }

  if (max_stream_backlog > 0) {
    long long stream_len = 0;
    if (!GetRedisStreamLength(redis_host, redis_port, stream_name, stream_len)) {
      g_notifications_rejected_total.fetch_add(1);
      LogJsonEvent("notification_rejected", "backpressure_check_failed", tenant_id);
      WriteHttpResponse(client_fd, 503, "Service Unavailable",
                        "{\"error\":\"failed to validate stream backlog\"}");
      close(client_fd);
      return;
    }
    if (stream_len >= max_stream_backlog) {
      g_notifications_rejected_total.fetch_add(1);
      g_backpressure_rejected_total.fetch_add(1);
      LogJsonEvent("notification_rejected", "stream_backpressure", tenant_id, "",
                   "stream=" + stream_name + ",length=" + std::to_string(stream_len));
      WriteHttpResponse(client_fd, 429, "Too Many Requests",
                        "{\"error\":\"ingress backpressure active\"}");
      close(client_fd);
      return;
    }
  }

  if (max_retry_stream_backlog > 0) {
    long long retry_stream_len = 0;
    if (!GetRedisStreamLength(redis_host, redis_port, retry_stream_name, retry_stream_len)) {
      g_notifications_rejected_total.fetch_add(1);
      LogJsonEvent("notification_rejected", "retry_backpressure_check_failed", tenant_id);
      WriteHttpResponse(client_fd, 503, "Service Unavailable",
                        "{\"error\":\"failed to validate retry stream backlog\"}");
      close(client_fd);
      return;
    }
    if (retry_stream_len >= max_retry_stream_backlog) {
      g_notifications_rejected_total.fetch_add(1);
      g_backpressure_rejected_total.fetch_add(1);
      LogJsonEvent("notification_rejected", "retry_stream_backpressure", tenant_id, "",
                   "stream=" + retry_stream_name + ",length=" +
                       std::to_string(retry_stream_len));
      WriteHttpResponse(client_fd, 429, "Too Many Requests",
                        "{\"error\":\"retry backpressure active\"}");
      close(client_fd);
      return;
    }
  }

  const std::string user_id = ExtractJsonStringField(req.body, "user_id").value_or("unknown-user");
  const std::string channel = ExtractJsonStringField(req.body, "channel").value_or("default");
  std::string correlation_id;
  // Check header first, then body, then generate if empty
  if (auto it = req.headers.find("x-correlation-id"); it != req.headers.end()) {
    correlation_id = it->second;
  }
  if (correlation_id.empty()) {
    auto from_body = ExtractJsonStringField(req.body, "correlation_id");
    if (from_body.has_value() && !from_body->empty()) {
      correlation_id = from_body.value();
    }
  }
  if (correlation_id.empty()) {
    correlation_id = GenerateCorrelationId();
  }

  std::string idempotency_key;
  if (auto it = req.headers.find("idempotency-key"); it != req.headers.end()) {
    idempotency_key = it->second;
  }
  if (idempotency_key.empty()) {
    auto from_body = ExtractJsonStringField(req.body, "idempotency_key");
    if (from_body.has_value() && !from_body->empty()) {
      idempotency_key = from_body.value();
    }
  }

  if (!idempotency_key.empty()) {
    const auto claim =
        ClaimIdempotency(storage_host, storage_port, tenant_id, idempotency_key, correlation_id);
    if (!claim.ok) {
      g_notifications_rejected_total.fetch_add(1);
      LogJsonEvent("notification_rejected", "idempotency_claim_failed", tenant_id, correlation_id);
      WriteHttpResponse(client_fd, 503, "Service Unavailable",
                        "{\"error\":\"failed to validate idempotency key\"}");
      close(client_fd);
      return;
    }
    if (!claim.claimed) {
      const std::string existing_id =
          claim.notification_id.empty() ? correlation_id : claim.notification_id;
      LogJsonEvent("notification_accepted", "duplicate_idempotency_key", tenant_id, existing_id);
      std::ostringstream response;
      response << "{\"status\":\"accepted\",\"deduplicated\":true,\"tenant_id\":\"" << tenant_id
               << "\",\"stream\":\"" << stream_name
               << "\",\"correlation_id\":\"" << existing_id << "\"}";
      WriteHttpResponse(client_fd, 202, "Accepted", response.str());
      close(client_fd);
      return;
    }
  }

  std::unordered_map<std::string, std::string> fields = {
      {"tenant_id", tenant_id},
      {"user_id", user_id},
      {"channel", channel},
      {"content", content.value()},
      {"correlation_id", correlation_id},
  };

  std::string redis_reply;
  if (!PublishToRedisStream(redis_host, redis_port, stream_name, fields, redis_reply)) {
    if (!idempotency_key.empty()) {
      const bool released =
          ReleaseIdempotency(storage_host, storage_port, tenant_id, idempotency_key, correlation_id);
      if (!released) {
        LogJsonEvent("notification_rejected", "idempotency_release_failed", tenant_id, correlation_id);
      }
    }
    g_notifications_rejected_total.fetch_add(1);
    LogJsonEvent("notification_rejected", "redis_publish_failed", tenant_id, correlation_id);
    WriteHttpResponse(client_fd, 503, "Service Unavailable",
                      "{\"error\":\"failed to publish to redis stream\"}");
    close(client_fd);
    return;
  }

  g_notifications_accepted_total.fetch_add(1);
  LogJsonEvent("notification_accepted", "ok", tenant_id, correlation_id);
  std::ostringstream response;
  response << "{\"status\":\"accepted\",\"tenant_id\":\"" << tenant_id
           << "\",\"stream\":\"" << stream_name
           << "\",\"correlation_id\":\"" << correlation_id << "\"}";
  WriteHttpResponse(client_fd, 202, "Accepted", response.str());
  close(client_fd);
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
  const std::string storage_host = std::getenv("STORAGE_HOST") ? std::getenv("STORAGE_HOST") : "127.0.0.1";
  const auto storage_port_value = ParseIntEnv("STORAGE_PORT", 8090);
  if (!storage_port_value.has_value()) {
    std::cerr << "Invalid numeric environment value for STORAGE_PORT.\n";
    return 1;
  }
  const int storage_port = storage_port_value.value();
  const std::string stream_name =
      std::getenv("REDIS_STREAM_NAME") ? std::getenv("REDIS_STREAM_NAME") : "notifications_stream";
  const std::string retry_stream_name =
      std::getenv("REDIS_RETRY_STREAM_NAME")
          ? std::getenv("REDIS_RETRY_STREAM_NAME")
          : "notifications_retry_stream";
  const std::string jwt_hs256_secret =
      std::getenv("JWT_HS256_SECRET") ? std::getenv("JWT_HS256_SECRET") : "";
  const bool gateway_require_auth = ParseBoolEnv("GATEWAY_REQUIRE_AUTH", false);
  const auto jwt_clock_skew_seconds_value = ParseIntEnv("JWT_CLOCK_SKEW_SECONDS", 60);
  if (!jwt_clock_skew_seconds_value.has_value()) {
    std::cerr << "Invalid numeric environment value for JWT_CLOCK_SKEW_SECONDS.\n";
    return 1;
  }
  const long long jwt_clock_skew_seconds = jwt_clock_skew_seconds_value.value();
  const auto tenant_rate_limit_value = ParseIntEnv("TENANT_RATE_LIMIT_PER_MINUTE", 0);
  if (!tenant_rate_limit_value.has_value()) {
    std::cerr << "Invalid numeric environment value for TENANT_RATE_LIMIT_PER_MINUTE.\n";
    return 1;
  }
  const int tenant_rate_limit_per_minute = tenant_rate_limit_value.value();
  const auto tenant_daily_quota_value = ParseIntEnv("TENANT_DAILY_QUOTA", 0);
  if (!tenant_daily_quota_value.has_value()) {
    std::cerr << "Invalid numeric environment value for TENANT_DAILY_QUOTA.\n";
    return 1;
  }
  const int tenant_daily_quota = tenant_daily_quota_value.value();
  const auto max_stream_backlog_value = ParseIntEnv("GATEWAY_MAX_STREAM_BACKLOG", 0);
  const auto max_retry_stream_backlog_value = ParseIntEnv("GATEWAY_MAX_RETRY_STREAM_BACKLOG", 0);
  if (!max_stream_backlog_value.has_value() || !max_retry_stream_backlog_value.has_value()) {
    std::cerr << "Invalid numeric environment value for stream backlog limits.\n";
    return 1;
  }
  const int max_stream_backlog = max_stream_backlog_value.value();
  const int max_retry_stream_backlog = max_retry_stream_backlog_value.value();

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

    std::thread([client_fd, redis_host, redis_port, stream_name, retry_stream_name, storage_host,
                 storage_port,
                 jwt_hs256_secret, gateway_require_auth, jwt_clock_skew_seconds,
                 tenant_rate_limit_per_minute, tenant_daily_quota, max_stream_backlog,
                 max_retry_stream_backlog]() {
      HandleClientConnection(client_fd, redis_host, redis_port, stream_name, retry_stream_name,
                             storage_host, storage_port, jwt_hs256_secret, gateway_require_auth,
                             jwt_clock_skew_seconds, tenant_rate_limit_per_minute,
                             tenant_daily_quota, max_stream_backlog, max_retry_stream_backlog);
    }).detach();
  }

  close(server_fd);
  return 0;
}
