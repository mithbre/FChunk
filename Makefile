CC=gcc
CFLAGS=-s -O2
LDFLAGS=libgcrypt-config --cflags --libs

default:
	$(CC) -o t src/block_hash.c src/fileops.c -std=c99 -DDEBUG `$(LDFLAGS)`

optim:
	$(CC) -o t src/block_hash.c src/fileops.c -std=c99 $(CFLAGS) `$(LDFLAGS)`
