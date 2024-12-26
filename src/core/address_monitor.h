#ifndef SRC_CORE_ADDRESS_MONITOR_H_
#define SRC_CORE_ADDRESS_MONITOR_H_

#include <functional>
#include <optional>
#include <string>

namespace dynamic_dns::core {

class AddressMonitor {
 public:
  struct Dependencies {
    std::function<std::optional<std::string>(void)> get_my_ipv4_address;
    // Returns whether the partner was successfully notified of the change.
    std::function<bool(std::string)> on_address_change;
  };

  AddressMonitor(Dependencies deps)
      : get_my_ipv4_address_(deps.get_my_ipv4_address),
        on_address_change_(deps.on_address_change) {}

  // Neither movable nor copyable.
  AddressMonitor(AddressMonitor&&) = delete;

  void Run();

 private:
  static constexpr const char* kLastKnownAddressFile = "last_known_address";

  void PrivateRun();

  std::optional<std::string> PollRealAddress();
  std::optional<std::string> GetStoredAddress();

  void WriteAddressToLkaFile(std::string address);

  std::function<std::optional<std::string>(void)> get_my_ipv4_address_;
  std::function<bool(std::string)> on_address_change_;
};

}  // namespace dynamic_dns::core

#endif  // SRC_CORE_ADDRESS_MONITOR_H_
