
# protobuf_generate(PROTO_SRCS PROTO_HDRS packet.proto PROTOC_OPTIONS --experimental_allow_proto3_optional)



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

protobuf_generate(
    TARGET src.protobuf.packet
    LANGUAGE cpp
    PROTOS packet.proto
    # [OUT_VAR <out_var>]
    # [EXPORT_MACRO <macro>]
    # [PROTOC_OUT_DIR <dir>]
    # [PLUGIN <plugin>]
    # [PLUGIN_OPTIONS <plugin_options>]
    # [DEPENDENCIES <depends]
    # [PROTOS <protobuf_files>]
    # [IMPORT_DIRS <dirs>]
    # [GENERATE_EXTENSIONS <extensions>]
    PROTOC_OPTIONS "--experimental_allow_proto3_optional"
)