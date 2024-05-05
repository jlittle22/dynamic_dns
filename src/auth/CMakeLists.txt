
set(AUTH_TARGET src.auth.auth)

add_library(${AUTH_TARGET})

target_sources(${AUTH_TARGET}
  PUBLIC
    auth.h
)

target_sources(${AUTH_TARGET}
  PUBLIC
    auth.cc
)

target_include_directories(${AUTH_TARGET}
  PUBLIC
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(${AUTH_TARGET}
  PUBLIC
    mbedtls
)

target_link_libraries(${AUTH_TARGET}
  PRIVATE
    src.common.assert
)

set(AUTH_TEST_TARGET "${AUTH_TARGET}_test")

add_executable(${AUTH_TEST_TARGET})

target_sources(${AUTH_TEST_TARGET}
  PRIVATE
    auth_test.cc
)

target_link_libraries(${AUTH_TEST_TARGET}
  PRIVATE
    ${AUTH_TARGET}
    GTest::gmock_main
    src.common.assert
)

include(GoogleTest)
gtest_discover_tests(${AUTH_TEST_TARGET})
