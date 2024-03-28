cmake_minimum_required(VERSION 3.22)
project(dynamic_dns
  VERSION 1.0
  DESCRIPTION "Dynamic DNS"
  LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED YES)

# Error on everything when build C++ targets.
set(CMAKE_CXX_FLAGS "-Wall -Wextra -Werror")

# Need to find gTest before recursing into subdirectories since we're keeping
# unit tests next to the modules they're testing.
#
# NOTE: Installing gTest via HTTPS is required to guarantee gMock is present
# which isn't included by default in some distributions.
include(FetchContent)
FetchContent_Declare(
  googletest
  DOWNLOAD_EXTRACT_TIMESTAMP true
  URL https://github.com/google/googletest/archive/b3a9ba2b8e975550799838332803d468797ae2e1.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_subdirectory(src)
