#define LOG_TAG "AddressMonitor"
#include "src/core/address_monitor.h"

#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <optional>
#include <regex>
#include <string>
#include <thread>

#include "src/common/assert.h"
#include "src/common/log.h"
#include "src/core/config.h"

namespace dynamic_dns::core {
namespace {

bool IsValidIpv4Address(std::string candidate) {
  std::regex ipv4Regex(R"(^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$)");
  return std::regex_match(candidate, ipv4Regex);
}

void LogLastWriteTime(std::filesystem::path file) {
  std::filesystem::file_time_type last_write_time =
      std::filesystem::last_write_time(file);

  auto as_time_t = std::chrono::system_clock::to_time_t(
      std::chrono::file_clock::to_sys(last_write_time));

  std::tm* local_time = std::localtime(&as_time_t);
  char buffer[80];
  std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", local_time);

  LOGI("LKA file last modified: %s\n", buffer);
}

}  // namespace

void AddressMonitor::Run() {
  while (true) {
    PrivateRun();
    std::this_thread::sleep_for(config::kIpChangeRequeryDuration);
  }
}

void AddressMonitor::PrivateRun() {
  std::optional<std::string> stored_address = GetStoredAddress();
  if (!stored_address) {
    LOGW("Couldn't retrieve stored address.\n");
  } else {
    LOGI("Stored address -> %s\n", (*stored_address).c_str());
  }

  std::optional<std::string> real_address = PollRealAddress();
  if (!real_address) {
    LOGW("Couldn't retrieve real address.\n");
  } else {
    LOGI("Real address -> %s\n", (*real_address).c_str());
  }

  if (real_address == stored_address) {
    LOGI("Addresses match.\n");
    return;
  }

  if (!on_address_change_(*real_address)) {
    LOGW("Skipping write to LKA file.\n");
    return;
  }

  WriteAddressToLkaFile(*real_address);
}

std::optional<std::string> AddressMonitor::PollRealAddress() {
  std::optional<std::string> real_address = get_my_ipv4_address_();
  if (!real_address) {
    return std::nullopt;
  }

  if (!IsValidIpv4Address(*real_address)) {
    LOGE("Network submodule returned an invalid address: %s. Ignoring.\n",
         (*real_address).c_str());
    return std::nullopt;
  }

  return *real_address;
}

std::optional<std::string> AddressMonitor::GetStoredAddress() {
  std::filesystem::path installation_directory = config::kInstallationPath;
  ASSERT(std::filesystem::is_directory(installation_directory),
         "Installation path is not a directory.");

  std::filesystem::path last_known_address_file =
      installation_directory / kLastKnownAddressFile;

  if (!std::filesystem::exists(last_known_address_file)) {
    LOGW("LKA file doesn't exist.\n");
    return std::nullopt;
  }

  ASSERT(std::filesystem::is_regular_file(last_known_address_file),
         "LKA file is not a regular file.");

  LogLastWriteTime(last_known_address_file);

  std::ifstream lka_stream(last_known_address_file);

  if (!lka_stream.is_open()) {
    LOGE("Failed to open LKA file.");
    return std::nullopt;
  }

  std::string line;
  ASSERT(std::getline(lka_stream, line), "Failed to return LKA file line.");

  if (!IsValidIpv4Address(line)) {
    LOGE("'%s' is not a valid IPv4 address. Ignoring.\n", line.c_str());
    return std::nullopt;
  }

  return line;
}

void AddressMonitor::WriteAddressToLkaFile(std::string address) {
  std::filesystem::path installation_directory = config::kInstallationPath;

  std::filesystem::path last_known_address_file =
      installation_directory / kLastKnownAddressFile;

  std::ofstream lka_stream(last_known_address_file, std::ios::trunc);
  if (!lka_stream.is_open()) {
    LOGE("Failed to write new address to LKA file.\n");
    return;
  }

  // Write the newline character for human readability. <3
  lka_stream << address << std::endl;

  LOGI("Wrote LKA.\n");
}

}  // namespace dynamic_dns::core
