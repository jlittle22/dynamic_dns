
#ifndef SRC_COMMON_ASSERT_H_
#define SRC_COMMON_ASSERT_H_

#include <cstdio>
#include <exception>

#define ASSERT(condition, message)                                      \
  do {                                                                  \
    if (!(condition)) {                                                 \
      fprintf(stderr,                                                   \
              "Condition %s failed at %s:%d failed with message: %s\n", \
              #condition, __FILE__, __LINE__, message);                 \
      std::terminate();                                                 \
    }                                                                   \
  } while (false)

#define CRASH(message)                                                       \
  do {                                                                       \
    fprintf(stderr, "Crash triggered at %s:%d with message: %s\n", __FILE__, \
            __LINE__, message);                                              \
    std::terminate();                                                        \
  } while (false)

#endif  // SRC_COMMON_ASSERT_H_
