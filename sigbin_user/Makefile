CC=gcc
CFALGS=
LDFLAGS=
INCLUDES=
BUILD_DIR=./build

%.c: *.c
	$(CC) -c $*.c -o$(BUILD_DIR)/$*.o

make:
	make *.c
	gcc $(BUILD_DIR)/*.o -o sigbin
