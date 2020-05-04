set(SOURCES
    quiclan.cpp
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${QUICLAN_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUICLAN_CXX_FLAGS}")

add_library(core STATIC ${SOURCES})

#target_compile_options(core PRIVATE
#     $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:
#        ${CLANG_GCC_WARNING_FLAGS}>
#     $<$<CXX_COMPILER_ID:MSVC>:
#        ${MSVC_WARNING_FLAGS}>)
