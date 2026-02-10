#ifndef REQUEST_CONTEXT_H
#define REQUEST_CONTEXT_H

#include <string>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <atomic>

namespace notification_platform {

// Single source of truth for request context across all services.
// Eliminates parameter bloat and ensures consistent ID propagation.
struct RequestContext {
  std::string correlation_id;  // Stable business identifier - never changes
  std::string tenant_id;       // Tenant isolation boundary
  std::string notification_id; // Business entity identifier
  
  RequestContext() = default;
  
  RequestContext(const std::string& corr_id, const std::string& ten_id, 
                 const std::string& notif_id = "")
      : correlation_id(corr_id), tenant_id(ten_id), notification_id(notif_id) {}
  
  bool IsValid() const {
    return !correlation_id.empty() && !tenant_id.empty();
  }
};

// Generates correlation_id exactly once at ingress
inline std::string GenerateCorrelationId() {
  static std::atomic<unsigned long long> seq{0};
  std::ostringstream out;
  out << "corr-" << static_cast<long long>(std::time(nullptr)) << "-"
      << seq.fetch_add(1);
  return out.str();
}

} // namespace notification_platform

#endif // REQUEST_CONTEXT_H
