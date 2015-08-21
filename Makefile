EXTRA_CFLAGS = 

CC = gcc
OBJS = parprouted.o

CFLAGS = -O2 -Wall $(EXTRA_CFLAGS)
LDFLAGS = -s

LIBS = 

all: parprouted

clean:
	rm -f $(OBJS) parprouted core

parprouted:	${OBJS}
	${CC} ${LDFLAGS} -o parprouted ${OBJS} ${LIBS}
