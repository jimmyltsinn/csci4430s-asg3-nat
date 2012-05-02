CC=gcc
CFLAGS=-Wall -O3
LDFLAGS=-lipq -lm

EXE=ipq_simple random_drop always_drop

all: $(EXE)

ipq_simple: 
	$(CC) $(CFLAGS) -o $@ $< $@.c $(LDFLAGS)

random_drop:
	$(CC) $(CFLAGS) -o $@ $< $@.c $(LDFLAGS)

always_drop:
	$(CC) $(CFLAGS) -o $@ $< $@.c $(LDFLAGS)

clean:
	rm -f $(EXE) $(OBJ)
