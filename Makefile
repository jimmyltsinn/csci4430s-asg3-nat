CC=gcc
CFLAGS=-Wall -g
LDFLAGS=-lipq

all: main

main: nat.o ck.o utility.o
	$(CC) $(CFLAGS) nat.o ck.o utility.o -o main $(LDFLAGS)

nat.o: nat.c nat.h
	$(CC) $(CFLAGS) nat.c -c

ck.o: ck.c 
	$(CC) $(CFLAGS) ck.c -c

utility.o: utility.c nat.h
	$(CC) $(CFLAGS) utility.c -c

clean: 
	rm -rf main *.o
