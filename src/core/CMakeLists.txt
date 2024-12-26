set(CONFIG_TARGET src.core.config)

add_library(${CONFIG_TARGET})

target_sources(${CONFIG_TARGET}
  PUBLIC
    config.h
)

target_include_directories(${CONFIG_TARGET}
  PUBLIC
    ${CMAKE_SOURCE_DIR}
)

set_target_properties(${CONFIG_TARGET} PROPERTIES LINKER_LANGUAGE CXX)

set(ADDRESS_MONITOR_TARGET src.core.address_monitor)

add_library(${ADDRESS_MONITOR_TARGET})

target_sources(${ADDRESS_MONITOR_TARGET}
  PUBLIC
    address_monitor.h
  PRIVATE
    address_monitor.cc
)

target_include_directories(${ADDRESS_MONITOR_TARGET}
  PUBLIC
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(${ADDRESS_MONITOR_TARGET}
  PRIVATE
    src.core.config
    src.common.assert
    src.common.log
)

set(NETWORK_TARGET src.core.network)

add_library(${NETWORK_TARGET})

target_sources(${NETWORK_TARGET}
  PUBLIC
    network.h
  PRIVATE
    network.cc
)

target_include_directories(${NETWORK_TARGET}
  PUBLIC
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(${NETWORK_TARGET}
  PRIVATE
    src.core.config
    src.common.assert
    src.common.log
    src.common.scope_guard
)

