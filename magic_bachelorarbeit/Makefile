# inspired by these videos: https://www.youtube.com/watch?v=LfIPVIsH4ZU https://www.youtube.com/watch?v=CRlqU9XzVr4

CC = gcc
CFLAGS = -g -Wall
OBJS = ./obj/galois.o ./obj/bignum.o ./obj/util.o
OBJS_MAIN_FILE = ./obj/main.o
OBJS_TEST = ./obj/galois_test.o
BIN = ./bin/main

all: $(BIN)

# linking for the actual program
$(BIN): $(OBJS) $(OBJS_MAIN_FILE)
	$(CC) $(CFLAGS) $(OBJS) $(OBJS_MAIN_FILE) -o $@

# compilation in machine code for the actual program
./obj/%.o: ./src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# linking for tests
./bin/test: $(OBJS_TEST) $(OBJS)
	$(CC) $(CFLAGS) $(OBJS_TEST) $(OBJS) -o $@

# compilation in machine code for tests and include header files from ./src
./obj/%.o: ./test/%.c
	$(CC) $(CFLAGS) -I./src -c $< -o $@

clean:
	rm -f ./bin/* ./obj/*
