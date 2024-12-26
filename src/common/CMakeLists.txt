# Assert target

set(ASSERT_TARGET src.common.assert)

add_library(${ASSERT_TARGET})

target_sources(${ASSERT_TARGET}
  PUBLIC
    assert.h
)

target_include_directories(${ASSERT_TARGET}
  PUBLIC
    ${CMAKE_SOURCE_DIR}
)

set_target_properties(${ASSERT_TARGET} PROPERTIES LINKER_LANGUAGE CXX)

set(LOG_TARGET src.common.log)

add_library(${LOG_TARGET})

target_sources(${LOG_TARGET}
  PUBLIC
    log.h
)

target_include_directories(${LOG_TARGET}
  PUBLIC
    ${CMAKE_SOURCE_DIR}
)

set_target_properties(${LOG_TARGET} PROPERTIES LINKER_LANGUAGE CXX)

set(SCOPE_GUARD src.common.scope_guard)

add_library(${SCOPE_GUARD})

target_sources(${SCOPE_GUARD}
  PUBLIC
    scope_guard.h
)

target_include_directories(${SCOPE_GUARD}
  PUBLIC
    ${CMAKE_SOURCE_DIR}
)

set_target_properties(${SCOPE_GUARD} PROPERTIES LINKER_LANGUAGE CXX)
