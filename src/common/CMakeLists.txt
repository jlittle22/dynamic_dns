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
