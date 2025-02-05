# inspired by these videos: https://www.youtube.com/watch?v=LfIPVIsH4ZU https://www.youtube.com/watch?v=CRlqU9XzVr4

CC = gcc
CFLAGS = -g -Wall
OBJS = $(wildcard ./obj/*.o)
BIN = ./bin/main

all: $(BIN)

# linking
$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@

# compilation in machine code
./obj/%.o: ./src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f ./bin/* ./obj/*
