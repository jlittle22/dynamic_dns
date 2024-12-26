#include "src/core/network.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/types.h>
#include <optional>
#include <string>

#include "src/common/scope_guard.h"

namespace dynamic_dns::core::network {

std::optional<std::string> GetMyIpv4Address() {
  // https://stackoverflow.com/questions/212528/how-can-i-get-the-ip-address-of-a-linux-machine
  // ... Yea.
  struct ifaddrs* if_addr_struct = nullptr;
  struct ifaddrs* ifa = nullptr;
  void* temp_addr_ptr = nullptr;

  getifaddrs(&if_addr_struct);

  ScopeGuard guard([&]() {
    if (if_addr_struct != nullptr) {
      freeifaddrs(if_addr_struct);
    }
  });

  for (ifa = if_addr_struct; ifa != nullptr; ifa = ifa->ifa_next) {
    if (!ifa->ifa_addr) {
      continue;
    }

    // Checks if we're handling an IPv4 address.
    if (ifa->ifa_addr->sa_family == AF_INET) {
      temp_addr_ptr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
      char address_buffer[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, temp_addr_ptr, address_buffer, INET_ADDRSTRLEN);
      printf("%s IP Address %s\n", ifa->ifa_name, address_buffer);
      // return std::string(address_buffer);
    }
  }

  return std::nullopt;
}

}  // namespace dynamic_dns::core::network
