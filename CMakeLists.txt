cmake_minimum_required(VERSION 3.14)

project(udp-vc
  VERSION 0.2.1
  DESCRIPTION "Simple SSL/TLS chat server & client"
  LANGUAGES C CXX
)

option(UDPVC_BUILD_TESTS "Build test binaries" OFF)

set(PROJECT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

configure_file(
  ${PROJECT_SOURCE_DIR}/shared/config.h.in
  ${PROJECT_SOURCE_DIR}/shared/config.h
)

find_package(OpenSSL REQUIRED)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/extern)
add_subdirectory(${PROJECT_SOURCE_DIR}/shared)
add_subdirectory(${PROJECT_SOURCE_DIR}/client)
add_subdirectory(${PROJECT_SOURCE_DIR}/server)

if (${UDPVC_BUILD_TESTS})
  enable_testing()
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tests)
endif()

target_include_directories(udpvc-client PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${PROJECT_SOURCE_DIR}/shared
  ${OPENSSL_INCLUDE_DIR}
  ${OPUS_INCLUDE_DIR}
)

target_include_directories(udpvc-server PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${PROJECT_SOURCE_DIR}/shared
  ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(udpvc-client
  ${OPENSSL_LIBRARIES}
  opus
  portaudio

  udpvc-shared
)

target_link_libraries(udpvc-server
  ${OPENSSL_LIBRARIES}
  udpvc-shared
)
