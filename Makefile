CC=gcc
LIBS=-lgcrypt
CFLAGS=
PREFIX=/usr/local

all: muzzle

debug: CFLAGS += -DDEBUG -g
debug: muzzle

muzzle.o: muzzle.c
	$(CC) $(CFLAGS) -c $< $(LIBS)

muzzle: muzzle.o
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

install: muzzle
	install -D -m 0755 muzzle $(DESTDIR)$(PREFIX)/bin/muzzle

clean:
	rm *.o muzzle

.PHONY: clean install
