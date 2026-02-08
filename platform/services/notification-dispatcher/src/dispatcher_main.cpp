#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

enum class RespType { kSimpleString, kError, kInteger, kBulkString, kArray, kNull };

struct RespValue {
  RespType type = RespType::kNull;
  std::string str;
  long long integer = 0;
  std::vector<RespValue> array;
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

bool ReadByte(int fd, char& out) { return recv(fd, &out, 1, 0) == 1; }

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

bool ReadLine(int fd, std::string& line) {
  line.clear();
  char prev = '\0';
  while (true) {
    char c = '\0';
    if (!ReadByte(fd, c)) {
      return false;
    }
    line.push_back(c);
    if (prev == '\r' && c == '\n') {
      line.pop_back();
      line.pop_back();
      return true;
    }
    prev = c;
  }
}

bool ParseRespValue(int fd, RespValue& out) {
  char prefix = '\0';
  if (!ReadByte(fd, prefix)) {
    return false;
  }

  if (prefix == '+') {
    out.type = RespType::kSimpleString;
    return ReadLine(fd, out.str);
  }
  if (prefix == '-') {
    out.type = RespType::kError;
    return ReadLine(fd, out.str);
  }
  if (prefix == ':') {
    out.type = RespType::kInteger;
    std::string line;
    if (!ReadLine(fd, line)) {
      return false;
    }
    try {
      out.integer = std::stoll(line);
      return true;
    } catch (...) {
      return false;
    }
  }
  if (prefix == '$') {
    std::string line;
    if (!ReadLine(fd, line)) {
      return false;
    }
    int len = 0;
    try {
      len = std::stoi(line);
    } catch (...) {
      return false;
    }
    if (len < 0) {
      out.type = RespType::kNull;
      return true;
    }
    out.type = RespType::kBulkString;
    std::string payload;
    if (!ReadExact(fd, payload, static_cast<size_t>(len + 2))) {
      return false;
    }
    out.str = payload.substr(0, static_cast<size_t>(len));
    return true;
  }
  if (prefix == '*') {
    std::string line;
    if (!ReadLine(fd, line)) {
      return false;
    }
    int count = 0;
    try {
      count = std::stoi(line);
    } catch (...) {
      return false;
    }
    if (count < 0) {
      out.type = RespType::kNull;
      return true;
    }
    out.type = RespType::kArray;
    out.array.clear();
    out.array.reserve(static_cast<size_t>(count));
    for (int i = 0; i < count; ++i) {
      RespValue child;
      if (!ParseRespValue(fd, child)) {
        return false;
      }
      out.array.push_back(std::move(child));
    }
    return true;
  }
  return false;
}

std::string BuildRespArray(const std::vector<std::string>& args) {
  std::string out = "*" + std::to_string(args.size()) + "\r\n";
  for (const auto& arg : args) {
    out += "$" + std::to_string(arg.size()) + "\r\n";
    out += arg + "\r\n";
  }
  return out;
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

int ConnectRedis(const std::string& host, int port) { return ConnectTcp(host, port); }

bool ExecRedis(int fd, const std::vector<std::string>& args, RespValue& out) {
  const std::string req = BuildRespArray(args);
  return SendAll(fd, req) && ParseRespValue(fd, out);
}

bool EnsureGroup(int fd, const std::string& stream, const std::string& group) {
  RespValue reply;
  if (!ExecRedis(fd, {"XGROUP", "CREATE", stream, group, "$", "MKSTREAM"}, reply)) {
    return false;
  }
  if (reply.type == RespType::kSimpleString && reply.str == "OK") {
    return true;
  }
  if (reply.type == RespType::kError && reply.str.find("BUSYGROUP") != std::string::npos) {
    return true;
  }
  return false;
}

std::unordered_map<std::string, std::string> FieldsFromResp(const RespValue& fields_array) {
  std::unordered_map<std::string, std::string> out;
  if (fields_array.type != RespType::kArray) {
    return out;
  }
  for (size_t i = 0; i + 1 < fields_array.array.size(); i += 2) {
    const auto& k = fields_array.array[i];
    const auto& v = fields_array.array[i + 1];
    if ((k.type == RespType::kBulkString || k.type == RespType::kSimpleString) &&
        (v.type == RespType::kBulkString || v.type == RespType::kSimpleString)) {
      out[k.str] = v.str;
    }
  }
  return out;
}

bool XAdd(int fd, const std::string& stream,
          const std::unordered_map<std::string, std::string>& fields) {
  std::vector<std::string> args = {"XADD", stream, "*"};
  for (const auto& [k, v] : fields) {
    args.push_back(k);
    args.push_back(v);
  }
  RespValue reply;
  if (!ExecRedis(fd, args, reply)) {
    return false;
  }
  return reply.type == RespType::kBulkString || reply.type == RespType::kSimpleString;
}

bool XAck(int fd, const std::string& stream, const std::string& group,
          const std::string& id) {
  RespValue reply;
  if (!ExecRedis(fd, {"XACK", stream, group, id}, reply)) {
    return false;
  }
  return reply.type == RespType::kInteger;
}

bool ReadNextBatch(int fd, const std::string& main_stream, const std::string& retry_stream,
                   const std::string& group, const std::string& consumer, int block_ms,
                   RespValue& out_reply) {
  return ExecRedis(fd, {"XREADGROUP", "GROUP", group, consumer, "COUNT", "10", "BLOCK",
                        std::to_string(block_ms), "STREAMS", main_stream, retry_stream, ">", ">"},
                   out_reply);
}

std::string GetField(const std::unordered_map<std::string, std::string>& fields,
                     const std::string& key, const std::string& fallback = "") {
  auto it = fields.find(key);
  if (it == fields.end()) {
    return fallback;
  }
  return it->second;
}

std::string JsonEscape(const std::string& input) {
  std::string out;
  out.reserve(input.size());
  for (char c : input) {
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
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

bool HttpPostJson(const std::string& host, int port, const std::string& path,
                  const std::string& body, int& status_code) {
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

  char buf[1024];
  std::string response;
  while (true) {
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) {
      break;
    }
    response.append(buf, static_cast<size_t>(n));
    if (response.size() > 1024 * 1024) {
      break;
    }
  }
  close(fd);

  size_t line_end = response.find("\r\n");
  if (line_end == std::string::npos) {
    return false;
  }
  std::istringstream status_line(response.substr(0, line_end));
  std::string http_version;
  if (!(status_line >> http_version >> status_code)) {
    return false;
  }
  return true;
}

bool PersistToStorage(const std::string& storage_host, int storage_port,
                      const std::string& notification_id,
                      const std::unordered_map<std::string, std::string>& fields,
                      const std::string& status, int attempt,
                      const std::string& error_msg) {
  std::ostringstream body;
  body << "{";
  body << "\"tenant_id\":\"" << JsonEscape(GetField(fields, "tenant_id", "unknown")) << "\",";
  body << "\"notification_id\":\"" << JsonEscape(notification_id) << "\",";
  body << "\"user_id\":\"" << JsonEscape(GetField(fields, "user_id", "unknown")) << "\",";
  body << "\"channel\":\"" << JsonEscape(GetField(fields, "channel", "default")) << "\",";
  body << "\"content\":\"" << JsonEscape(GetField(fields, "content", "")) << "\",";
  body << "\"status\":\"" << JsonEscape(status) << "\",";
  body << "\"attempt\":" << attempt << ",";
  body << "\"error\":\"" << JsonEscape(error_msg) << "\"";
  body << "}";

  int status_code = 0;
  if (!HttpPostJson(storage_host, storage_port, "/v1/internal/store", body.str(), status_code)) {
    return false;
  }
  return status_code >= 200 && status_code < 300;
}

bool PushToGatewayFeed(const std::string& gateway_host, int gateway_port,
                       const std::string& notification_id,
                       const std::unordered_map<std::string, std::string>& fields) {
  std::ostringstream body;
  body << "{";
  body << "\"notification_id\":\"" << JsonEscape(notification_id) << "\",";
  body << "\"tenant_id\":\"" << JsonEscape(GetField(fields, "tenant_id", "unknown")) << "\",";
  body << "\"user_id\":\"" << JsonEscape(GetField(fields, "user_id", "unknown")) << "\",";
  body << "\"channel\":\"" << JsonEscape(GetField(fields, "channel", "default")) << "\",";
  body << "\"content\":\"" << JsonEscape(GetField(fields, "content", "")) << "\"";
  body << "}";

  int status_code = 0;
  if (!HttpPostJson(gateway_host, gateway_port, "/v1/internal/deliver", body.str(), status_code)) {
    return false;
  }
  return status_code >= 200 && status_code < 300;
}

}  // namespace

int main() {
  const auto redis_port_opt = ParseIntEnv("REDIS_PORT", 6379);
  const auto storage_port_opt = ParseIntEnv("STORAGE_PORT", 8090);
  const auto gateway_port_opt = ParseIntEnv("GATEWAY_PORT", 8080);
  const auto block_ms_opt = ParseIntEnv("DISPATCHER_BLOCK_MS", 5000);
  const auto max_retries_opt = ParseIntEnv("DISPATCHER_MAX_RETRIES", 3);
  if (!redis_port_opt.has_value() || !storage_port_opt.has_value() || !gateway_port_opt.has_value() ||
      !block_ms_opt.has_value() || !max_retries_opt.has_value()) {
    std::cerr << "invalid numeric env config\n";
    return 1;
  }

  const std::string redis_host = std::getenv("REDIS_HOST") ? std::getenv("REDIS_HOST") : "127.0.0.1";
  const std::string storage_host = std::getenv("STORAGE_HOST") ? std::getenv("STORAGE_HOST") : "127.0.0.1";
  const std::string gateway_host = std::getenv("GATEWAY_HOST") ? std::getenv("GATEWAY_HOST") : "127.0.0.1";
  const int redis_port = redis_port_opt.value();
  const int storage_port = storage_port_opt.value();
  const int gateway_port = gateway_port_opt.value();

  const std::string stream = std::getenv("REDIS_STREAM_NAME")
                                 ? std::getenv("REDIS_STREAM_NAME")
                                 : "notifications_stream";
  const std::string retry_stream = std::getenv("REDIS_RETRY_STREAM_NAME")
                                       ? std::getenv("REDIS_RETRY_STREAM_NAME")
                                       : "notifications_retry_stream";
  const std::string dlq_stream = std::getenv("REDIS_DLQ_STREAM_NAME")
                                     ? std::getenv("REDIS_DLQ_STREAM_NAME")
                                     : "notifications_dlq_stream";
  const std::string group = std::getenv("DISPATCHER_GROUP")
                                ? std::getenv("DISPATCHER_GROUP")
                                : "notification_dispatcher_group";
  const std::string consumer = std::getenv("DISPATCHER_CONSUMER")
                                   ? std::getenv("DISPATCHER_CONSUMER")
                                   : "dispatcher-1";
  const int block_ms = block_ms_opt.value();
  const int max_retries = max_retries_opt.value();

  int redis_fd = ConnectRedis(redis_host, redis_port);
  if (redis_fd < 0) {
    std::cerr << "failed to connect to redis at " << redis_host << ":" << redis_port << "\n";
    return 1;
  }

  if (!EnsureGroup(redis_fd, stream, group) || !EnsureGroup(redis_fd, retry_stream, group)) {
    std::cerr << "failed to create/read stream groups\n";
    close(redis_fd);
    return 1;
  }

  std::cout << "notification-dispatcher consuming stream=" << stream << " group=" << group
            << " consumer=" << consumer << " storage=" << storage_host << ":" << storage_port
            << " gateway=" << gateway_host << ":" << gateway_port << "\n";

  while (true) {
    RespValue reply;
    if (!ReadNextBatch(redis_fd, stream, retry_stream, group, consumer, block_ms, reply)) {
      std::cerr << "xreadgroup failed, reconnecting...\n";
      close(redis_fd);
      std::this_thread::sleep_for(std::chrono::seconds(1));
      redis_fd = ConnectRedis(redis_host, redis_port);
      if (redis_fd < 0 || !EnsureGroup(redis_fd, stream, group) ||
          !EnsureGroup(redis_fd, retry_stream, group)) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
      }
      continue;
    }

    if (reply.type == RespType::kNull || reply.type != RespType::kArray || reply.array.empty()) {
      continue;
    }

    for (const auto& stream_entry : reply.array) {
      if (stream_entry.type != RespType::kArray || stream_entry.array.size() != 2) {
        continue;
      }
      const RespValue& stream_name_value = stream_entry.array[0];
      if (!(stream_name_value.type == RespType::kBulkString ||
            stream_name_value.type == RespType::kSimpleString)) {
        continue;
      }
      const std::string source_stream = stream_name_value.str;
      const RespValue& messages = stream_entry.array[1];
      if (messages.type != RespType::kArray) {
        continue;
      }

      for (const auto& msg : messages.array) {
        if (msg.type != RespType::kArray || msg.array.size() != 2) {
          continue;
        }
        const RespValue& id_value = msg.array[0];
        const RespValue& fields_value = msg.array[1];
        if (!(id_value.type == RespType::kBulkString || id_value.type == RespType::kSimpleString)) {
          continue;
        }

        const std::string message_id = id_value.str;
        auto fields = FieldsFromResp(fields_value);

        int retry_count = 0;
        try {
          retry_count = std::stoi(GetField(fields, "retry_count", "0"));
        } catch (...) {
          retry_count = 0;
        }

        bool should_fail = GetField(fields, "simulate_fail", "false") == "true";
        std::string failure_reason = should_fail ? "simulated_failure" : "";

        if (!PersistToStorage(storage_host, storage_port, message_id, fields, "received", retry_count,
                              "")) {
          should_fail = true;
          failure_reason = "storage_persist_failed_received";
        }

        if (!should_fail) {
          if (!PersistToStorage(storage_host, storage_port, message_id, fields, "delivered",
                                retry_count, "")) {
            should_fail = true;
            failure_reason = "storage_persist_failed_delivered";
          }
        }

        if (!should_fail) {
          if (!PushToGatewayFeed(gateway_host, gateway_port, message_id, fields)) {
            should_fail = true;
            failure_reason = "gateway_delivery_failed";
          }
        }

        if (!should_fail) {
          if (!XAck(redis_fd, source_stream, group, message_id)) {
            std::cerr << "xack failed for " << message_id << "\n";
          } else {
            std::cout << "delivered and acked id=" << message_id
                      << " tenant=" << GetField(fields, "tenant_id", "unknown") << "\n";
          }
          continue;
        }

        if (retry_count + 1 > max_retries) {
          fields["failure_reason"] =
              failure_reason.empty() ? "max_retries_exhausted" : failure_reason;
          fields["original_stream_id"] = message_id;
          fields["final_retry_count"] = std::to_string(retry_count + 1);

          PersistToStorage(storage_host, storage_port, message_id, fields, "dlq", retry_count + 1,
                           fields["failure_reason"]);

          if (!XAdd(redis_fd, dlq_stream, fields)) {
            std::cerr << "failed to route to dlq id=" << message_id << "\n";
          } else {
            std::cout << "routed to dlq id=" << message_id << "\n";
          }
          XAck(redis_fd, source_stream, group, message_id);
          continue;
        }

        fields["retry_count"] = std::to_string(retry_count + 1);
        fields["previous_stream_id"] = message_id;

        PersistToStorage(storage_host, storage_port, message_id, fields, "retry_scheduled",
                         retry_count + 1,
                         failure_reason.empty() ? "delivery_failed" : failure_reason);

        if (!XAdd(redis_fd, retry_stream, fields)) {
          std::cerr << "failed to publish retry event id=" << message_id << "\n";
          continue;
        }
        if (!XAck(redis_fd, source_stream, group, message_id)) {
          std::cerr << "xack failed after retry publish id=" << message_id << "\n";
        } else {
          std::cout << "retry scheduled id=" << message_id
                    << " retry_count=" << fields["retry_count"] << "\n";
        }
      }
    }
  }

  close(redis_fd);
  return 0;
}
