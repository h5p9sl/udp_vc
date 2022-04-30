enable_testing()

add_executable(udpvc-networking-tests
  tests.c
  networking_tests.c
)
target_link_libraries(udpvc-networking-tests udpvc-shared)

add_executable(udpvc-commands-tests
  tests.c
  commands_tests.c
)
target_link_libraries(udpvc-commands-tests udpvc-shared)

add_test(NAME "networking-packet-creation" COMMAND udpvc-networking-tests "creation")
add_test(NAME "networking-packet-sending-receiving" COMMAND udpvc-networking-tests "sending-and-receiving")

add_test(NAME "command-system-init" COMMAND udpvc-commands-tests "init")
add_test(NAME "command-system-execution" COMMAND udpvc-commands-tests "execution")
