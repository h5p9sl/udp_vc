CFLAGS=-std=c99 -Wall -Wextra

SERVER_SRC=server.c
SERVER_OUT=server

CLIENT_SRC=client.c
CLIENT_OUT=client

all: server client

debug: CFLAGS += --debug
debug: all

release: CFLAGS += --release
release: all

server: ${SERVER_SRC}
	${CC} ${CFLAGS} ${SERVER_SRC} -o ${SERVER_OUT}

client: ${CLIENT_SRC}
	${CC} ${CFLAGS} ${CLIENT_SRC} -o ${CLIENT_OUT} -lpulse -lpulse-simple -lopus -lpthread

clean:
	rm ${CLIENT_OUT} ${SERVER_OUT}
