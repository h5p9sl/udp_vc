cmake_minimum_required(VERSION 3.14)

project(udp-vc
  VERSION 0.2.0
  DESCRIPTION "Simple SSL/TLS chat server & client"
  LANGUAGES C
)

set(PROJECT_SOURCE_DIR src)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

configure_file(
  ${PROJECT_SOURCE_DIR}/shared/config.h.in
  ${PROJECT_SOURCE_DIR}/shared/config.h
)

find_package(OpenSSL REQUIRED)
find_package(PulseAudio REQUIRED)

add_subdirectory(extern)
add_subdirectory(${PROJECT_SOURCE_DIR}/shared)
add_subdirectory(${PROJECT_SOURCE_DIR}/client)
add_subdirectory(${PROJECT_SOURCE_DIR}/server)

target_include_directories(udpvc-client PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${PROJECT_SOURCE_DIR}/shared
)

target_include_directories(udpvc-server PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${PROJECT_SOURCE_DIR}/shared
)

target_link_libraries(udpvc-client
  ${OPENSSL_LIBRARIES}
  pulse
  pulse-simple
  opus

  udpvc-shared
)

target_link_libraries(udpvc-server
  ${OPENSSL_LIBRARIES}
  udpvc-shared
)
