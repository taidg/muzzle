CC=g++
LIBS=-lcrypto++
FLAGS=-Werror -Wall -Wfatal-errors

all: muzzle

muzzle.o: muzzle.cpp
	$(CC) $(FLAGS) -c $< $(LIBS)

muzzle: muzzle.o
	$(CC) $(FLAGS) -o $@ $< $(LIBS)

.PHONY: clean

clean:
	rm *.o muzzle

