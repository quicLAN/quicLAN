set(SOURCES
    endtoendtest.cpp
    unittest.cpp
    main.cpp
)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUICLAN_CXX_FLAGS}")

add_executable(quiclantest ${SOURCES})

target_link_libraries(quiclantest msquic quiclancore)