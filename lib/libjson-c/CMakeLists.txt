set(LIB_JSON_C "json-c" CACHE STRING "json-c")
include_directories(include/json-c)

file(GLOB_RECURSE SOURCES
    "src/*.c"
)
add_library(${LIB_JSON_C} ${SOURCES})
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/json-c"
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h")
target_include_directories(${LIB_JSON_C} PUBLIC include)
