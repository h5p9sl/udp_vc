set(SERVER_SOURCE
  main.c
  client_list.c
  server.c
)

add_executable(udpvc-server
  ${SERVER_SOURCE}
)

target_include_directories(udpvc-server PUBLIC
  ${OPENSSL_INCLUDE_DIR}
)
