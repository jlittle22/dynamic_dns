
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS packet.proto)

# Create MarketAnalyzer target

set(MESSAGE_PROTO_TARGET src.protobuf.packet)

add_library(${MESSAGE_PROTO_TARGET})

target_sources(${MESSAGE_PROTO_TARGET}
  PUBLIC
    ${PROTO_HDRS}
)

target_sources(${MESSAGE_PROTO_TARGET}
  PRIVATE
    ${PROTO_SRCS}
)

target_include_directories(${MESSAGE_PROTO_TARGET}
  PUBLIC
    ${CMAKE_CURRENT_BINARY_DIR}
)
