CC=gcc
CFLAGS=-s -O2
LDFLAGS=libgcrypt-config --cflags --libs

default:
	$(CC) -o t src/main.c src/fileops.c src/hashops.c -std=c99 -Wall -DDEBUG `$(LDFLAGS)`

optim:
	$(CC) -o t src/main.c src/fileops.c src/hashops.c -std=c99 $(CFLAGS) `$(LDFLAGS)`
