cmake_minimum_required(VERSION 3.7)
project(xnet)

include_directories(
        ${PROJECT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/lib/npcap/Include
        ${PROJECT_SOURCE_DIR}/src/net_app
        ${PROJECT_SOURCE_DIR}/src/tiny_net
        ${PROJECT_SOURCE_DIR}/lib/xnet
)
LINK_DIRECTORIES(${PROJECT_SOURCE_DIR}/lib/npcap/Lib/x64)

add_executable(${PROJECT_NAME}  src/app.c)
add_subdirectory(src/tiny_net)
add_subdirectory(src/net_app)
add_subdirectory(lib/xnet)
target_link_libraries(${PROJECT_NAME}  net_lib tiny_net net_app wpcap)


