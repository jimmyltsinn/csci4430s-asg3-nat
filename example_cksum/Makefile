CC=gcc
CFLAGS=-Wall -O3
LDFLAGS=-lipq -lm

EXE=ipq_simple

all: $(EXE)

ipq_simple: ipq_simple.o ck.o
	$(CC) $(CFLAGS) -o ipq_simple ipq_simple.o ck.o $(LDFLAGS)

clean:
	/bin/rm ck.o ipq_simple.o ipq_simple
