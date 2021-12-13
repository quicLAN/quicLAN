
add_library(quiclaninc INTERFACE)

target_compile_options(quiclaninc INTERFACE ${QUICLAN_C_FLAGS})
target_compile_options(quiclaninc INTERFACE $<$<COMPILE_LANGUAGE:CXX>:${QUICLAN_CXX_FLAGS}>)

target_include_directories(quiclaninc INTERFACE ${QUICLAN_INCLUDE_DIR})

target_compile_features(quiclaninc INTERFACE cxx_std_20)
target_compile_features(quiclaninc INTERFACE c_std_11)

target_link_libraries(quiclaninc INTERFACE inc)