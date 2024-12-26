#ifndef SRC_CORE_NETWORK_H_
#define SRC_CORE_NETWORK_H_

#include <optional>
#include <string>

namespace dynamic_dns::core::network {

std::optional<std::string> GetMyIpv4Address();

}  // namespace dynamic_dns::core::network

#endif  // SRC_CORE_NETWORK_H_
