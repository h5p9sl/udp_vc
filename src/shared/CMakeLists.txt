add_library(udpvc-shared
  polling.c
  networking.c
)
target_link_libraries(udpvc-shared ${OPENSSL_LIBRARIES})
target_include_directories(udpvc-shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
