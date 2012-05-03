CC=gcc
CFLAGS=-Wall -g
LDFLAGS=-lipq

all: nat

nat: nat.o ck.o utility.o nat_list.o
	$(CC) $(CFLAGS) nat.o nat_list.o ck.o utility.o -o nat $(LDFLAGS)

nat.o: nat.c nat.h
	$(CC) $(CFLAGS) nat.c -c

nat_list.o: nat_list.c nat.h list.h
	$(CC) $(CFLAGS) nat_list.c -c

ck.o: ck.c 
	$(CC) $(CFLAGS) ck.c -c

utility.o: utility.c nat.h
	$(CC) $(CFLAGS) utility.c -c

clean: 
	rm -rf nat *.o
