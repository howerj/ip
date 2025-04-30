CFLAGS=-Wall -Wextra -pedantic -O2 -std=gnu99
TARGET=ip

.PHONY: all default test run clean

all default: ${TARGET}

test run: ${TARGET}
	./${TARGET}

${TARGET}: ip.c ip.h
	${CC} ${CFLAGS} $< -o $@

clean:
	git clean -dffx
