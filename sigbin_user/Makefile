CC=gcc
CFALGS=
LDFLAGS=-lpolarssl
INCLUDES=
BUILD_DIR=./build

make:
	$(CC) -o $(BUILD_DIR)/cmd.o -c cmd.c
	$(CC) -o $(BUILD_DIR)/config.o -c config.c
	$(CC) -o $(BUILD_DIR)/crypt.o -c crypt.c
	$(CC) -o $(BUILD_DIR)/debug.o -c debug.c
	$(CC) -o $(BUILD_DIR)/elf_op.o -c elf_op.c
	$(CC) -o $(BUILD_DIR)/hash.o -c hash.c
	$(CC) -o $(BUILD_DIR)/key.o -c key.c
	$(CC) -o $(BUILD_DIR)/section.o -c section.c
	$(CC) -o $(BUILD_DIR)/sigbin.o -c sigbin.c
	$(CC) -o $(BUILD_DIR)/utils.o -c utils.c
	$(CC) $(CFLAGS) $(LDFALGS) $(BUILD_DIR)/*.o -o sigbin

clean:
	rm -f $(BUILD_DIR)/*.o
	rm -f sigbin
