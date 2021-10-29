CFLAGS=-std=c99 -Wall

SRC=server.c
OUT=server

${OUT}: ${SRC}
	${CC} ${CFLAGS} ${SRC} -o ${OUT}

clean:
	rm ${OUT}
