CC=gcc
CFLAGS=-s -O2
LDFLAGS=libgcrypt-config --cflags --libs

default:
	$(CC) -o t block_hash.c -std=c99 `$(LDFLAGS)`

optim:
	$(CC) -o t block_hash.c -std=c99 $(CFLAGS) `$(LDFLAGS)`
