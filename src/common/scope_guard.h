#ifndef SRC_COMMON_SCOPE_GUARD_H_
#define SRC_COMMON_SCOPE_GUARD_H_

#include <functional>

namespace dynamic_dns::core {

class ScopeGuard {
 public:
  ScopeGuard(std::function<void(void)> fire) : fire_(fire) {}

  ~ScopeGuard() {
    if (fire_) {
      fire_();
    }
  }

  ScopeGuard() = delete;
  ScopeGuard(ScopeGuard&&) = delete;

  void Disarm() { fire_ = nullptr; }

 private:
  std::function<void(void)> fire_;
};

}  // namespace dynamic_dns::core

#endif  // SRC_COMMON_SCOPE_GUARD_H_