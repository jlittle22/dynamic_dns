add_subdirectory(auth)
add_subdirectory(common)
add_subdirectory(core)
add_subdirectory(protobuf)

set(DYNAMIC_DNS_TARGET partner)

add_executable(${DYNAMIC_DNS_TARGET})

target_sources(${DYNAMIC_DNS_TARGET}
  PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/main.cc
)

target_link_libraries(${DYNAMIC_DNS_TARGET}
  PRIVATE
    src.core.address_monitor
    src.core.config
    src.core.network
    src.common.log
    src.protobuf.packet

)
