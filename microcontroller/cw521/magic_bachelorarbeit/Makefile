# inspired by these videos: https://www.youtube.com/watch?v=LfIPVIsH4ZU https://www.youtube.com/watch?v=CRlqU9XzVr4

CC = gcc
CFLAGS = -g -Wall -Wextra -D LOCAL
OBJS = ./obj/galois.o ./obj/bignum.o ./obj/util_functions.o ./obj/salsa20.o ./obj/magic_mode.o ./obj/hamming_code.o ./obj/examples.o
OBJ_MAIN_FILE = ./obj/main.o
BIN_MAIN = ./bin/main.bin
OBJS_TEST = ./obj/test_galois.o ./obj/test_bignum.o ./obj/test_util_functions.o ./obj/test_salsa20.o ./obj/test_magic_mode.o ./obj/test_hamming_code.o
OBJ_MAIN_TEST_FILE = ./obj/test_main.o
BIN_TEST_MAIN = ./bin/test.bin

# run the program without tests
all: $(BIN_MAIN)

# linking for the actual program
$(BIN_MAIN): $(OBJS) $(OBJ_MAIN_FILE)
	$(CC) $(CFLAGS) $(OBJS) $(OBJ_MAIN_FILE) -o $@ -lm

# compilation in machine code for the actual program
./obj/%.o: ./src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# running all tests
test: $(BIN_TEST_MAIN)

# linking for the actual program for tests
$(BIN_TEST_MAIN): $(OBJS) $(OBJS_TEST) $(OBJ_MAIN_TEST_FILE)
	$(CC) $(CFLAGS) $(OBJS) $(OBJS_TEST) $(OBJ_MAIN_TEST_FILE) -o $@ -lm

# compilation in machine code for tests and include header files from ./src
./obj/%.o: ./test/%.c
	$(CC) $(CFLAGS) -I./src -c $< -o $@

clean:
	rm -f ./bin/*.bin ./obj/*.o
