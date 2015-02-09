CC=g++
LIBS=-lgcrypt
CXXFLAGS=-std=c++11

all: muzzle

debug: CXXFLAGS += -DDEBUG -g
debug: muzzle

muzzle.o: muzzle.cc
	$(CC) $(CXXFLAGS) -c $< $(LIBS)

muzzle: muzzle.o
	$(CC) $(CXXFLAGS) -o $@ $< $(LIBS)

.PHONY: clean

clean:
	rm *.o muzzle

