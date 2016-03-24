CC=gcc
LIBS=-lgcrypt
CFLAGS=-Wfatal-errors

all: muzzle

debug: CFLAGS += -DDEBUG -g
debug: muzzle

muzzle.o: muzzle.c
	$(CC) $(CFLAGS) -c $< $(LIBS)

muzzle: muzzle.o
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

.PHONY: clean

clean:
	rm *.o muzzle

