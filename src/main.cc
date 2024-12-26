#define LOG_TAG "main"

#include <thread>

#include "src/common/log.h"
#include "src/core/address_monitor.h"
#include "src/core/config.h"
#include "src/core/network.h"

using namespace dynamic_dns;

namespace {
bool HandleAddressChange(std::string new_address) {
  LOGI("New address detected -> %s\n", new_address.c_str());
  return true;
}

core::AddressMonitor address_monitor(core::AddressMonitor::Dependencies{
    .get_my_ipv4_address = core::network::GetMyIpv4Address,
    .on_address_change = HandleAddressChange,
});
}  // namespace

int main() {
  LOGI("Installation directory -> %s\n", core::config::kInstallationPath);

  LOGI("Spawning threads... ");

  std::array<std::thread, 1> threads = {
      std::thread([&]() { address_monitor.Run(); }),
  };

  SPARSE_LOGI("Done.\n");

  for (auto& t : threads) {
    t.join();
  }

  LOGI("Shutting down.\n");

  return 0;
}
