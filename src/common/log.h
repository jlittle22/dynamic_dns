#ifndef SRC_COMMON_LOG_H_
#define SRC_COMMON_LOG_H_

#include <cstdio>

#ifndef LOG_TAG
#error "LOG_TAG must be defined prior to log.h header inclusion."
#endif

#define RED "\033[0;31m"
#define GREEN "\033[0;32m"
#define YELLOW "\033[0;33m"
#define DEFAULT "\033[0m"

// Honestly, I dont remember why you need this nesting mechanism, but you 100%
// do need it.
#define STRINGIFY(x) STRINGIFY_NESTED(x)
#define STRINGIFY_NESTED(x) #x

#define FILE_AND_LINE __FILE__ ":" STRINGIFY(__LINE__)

#define LOGI(...) \
  fprintf(stdout, \
          FILE_AND_LINE GREEN " [INFO]" DEFAULT "[" LOG_TAG "] " __VA_ARGS__)
#define LOGW(...) \
  fprintf(stderr, \
          FILE_AND_LINE YELLOW " [WARN]" DEFAULT "[" LOG_TAG "] " __VA_ARGS__)
#define LOGE(...) \
  fprintf(stderr, \
          FILE_AND_LINE RED " [ERROR]" DEFAULT "[" LOG_TAG "] " __VA_ARGS__)

#define SPARSE_LOGI(...) fprintf(stdout, __VA_ARGS__);
#define SPARSE_LOGE(...) fprintf(stderr, __VA_ARGS__);

#endif  // SRC_COMMON_LOG_H_
