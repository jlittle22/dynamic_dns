#ifndef SRC_CORE_CONFIG_H_
#define SRC_CORE_CONFIG_H_

#include <chrono>

namespace dynamic_dns::core::config {

// Dynamic DNS will look for and create files in the installation directory.
inline constexpr const char* kInstallationPath =
    "/home/jsnl/dynamic_dns_partner_a";

inline constexpr std::chrono::milliseconds kIpChangeRequeryDuration =
    std::chrono::minutes(1);

}  // namespace dynamic_dns::core::config

#endif  // SRC_CORE_CONFIG_H_
