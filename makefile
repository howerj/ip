CFLAGS=-Wall -Wextra -pedantic -O2 -std=gnu99 -Wno-unused-function
TARGET=ip

.PHONY: all default test run clean

all default: ${TARGET}

test run: ${TARGET}
	./${TARGET}

${TARGET}: ip.c ip.h makefile
	${CC} ${CFLAGS} $< -o $@

clean:
	git clean -dffx
