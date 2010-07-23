CC = gcc
CFLAGS = -Wall

tnfuse: tnfuse.c errors.h commands.h config.h
	$(CC) $(CFLAGS) `pkg-config fuse --cflags --libs` tnfuse.c -o tnfuse -lm
