add_executable(udpvc-client
  main.c
  audio_system.c
  client.c
)

target_include_directories(udpvc-client PUBLIC
  ${OPENSSL_INCLUDE_DIR}
)
