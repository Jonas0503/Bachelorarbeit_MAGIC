# inspired by these videos: https://www.youtube.com/watch?v=LfIPVIsH4ZU https://www.youtube.com/watch?v=CRlqU9XzVr4

CC = gcc
CFLAGS = -g -Wall -lc
OBJS = ./obj/galois.o ./obj/bignum.o ./obj/util.o ./obj/salsa20.o
OBJ_MAIN_FILE = ./obj/main.o
BIN_TEST_GALOIS = ./bin/test_galois
BIN_TEST_BIGNUM = ./bin/test_bignum
BIN_TESTS = $(BIN_TEST_BIGNUM) $(BIN_TEST_GALOIS)
BIN_MAIN = ./bin/main

# run the program without tests
all: $(BIN_MAIN)

# linking for the actual program
$(BIN_MAIN): $(OBJS) $(OBJ_MAIN_FILE)
	$(CC) $(CFLAGS) $(OBJS) $(OBJ_MAIN_FILE) -o $@

# compilation in machine code for the actual program
./obj/%.o: ./src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# running all tests
test: $(BIN_TESTS)
	$(BIN_TEST_BIGNUM)
	$(BIN_TEST_GALOIS)

# linking for galois tests
$(BIN_TEST_GALOIS): ./obj/test_galois.o $(OBJS)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@

# linking for bignum tests
$(BIN_TEST_BIGNUM): ./obj/test_bignum.o $(OBJS)
	$(CC) $(CFLAGS) $< $(OBJS) -o $@

# compilation in machine code for tests and include header files from ./src
./obj/%.o: ./test/%.c
	$(CC) $(CFLAGS) -I./src -c $< -o $@

clean:
	rm -f ./bin/* ./obj/*
