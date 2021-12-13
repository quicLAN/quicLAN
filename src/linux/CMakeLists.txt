
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUICLAN_CXX_FLAGS}")

add_executable(quiclan main.cpp)

target_link_libraries(quiclan msquic quiclancore openssl)
