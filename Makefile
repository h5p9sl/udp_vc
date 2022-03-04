CFLAGS=-std=c99 -Wall -Wextra -lssl -lcrypto -Isrc

SERVER_SRC=src/server/*.c src/polling.c
SERVER_OUT=server

CLIENT_SRC=src/client/*.c src/polling.c
CLIENT_OUT=client

all: server client

debug: CFLAGS += --debug
debug: all

release: CFLAGS += --release -O2
release: all

server: ${SERVER_SRC}
	${CC} ${CFLAGS} ${SERVER_SRC} -o ${SERVER_OUT}

client: ${CLIENT_SRC}
	${CC} ${CFLAGS} ${CLIENT_SRC} -o ${CLIENT_OUT} -lpulse -lpulse-simple -lopus -lpthread

clean:
	rm ${CLIENT_OUT} ${SERVER_OUT}
