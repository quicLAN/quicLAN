
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUICLAN_CXX_FLAGS}")

add_executable(quiclantest main.cpp)

target_link_libraries(quiclantest msquic quiclancore)