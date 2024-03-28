set(DYNAMIC_DNS_TARGET src.main)

add_executable(${DYNAMIC_DNS_TARGET})

### Sources
target_sources(${DYNAMIC_DNS_TARGET}
  PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/main.cc
)
