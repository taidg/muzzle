CC=g++
LIBS=-lcrypto++ -lgcrypt
FLAGS=-Werror -Wall -Wfatal-errors -std=c++11

all: muzzle

muzzle.o: muzzle.cc
	$(CC) $(FLAGS) -c $< $(LIBS)

muzzle: muzzle.o
	$(CC) $(FLAGS) -o $@ $< $(LIBS)

.PHONY: clean

clean:
	rm *.o muzzle

