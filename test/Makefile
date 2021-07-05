all: testdoc test1 test1b test2 test1-32 test2-32 sizes sizes32

testdoc: test.c
	$(CC) -DTESTDOC -Os -W -Wall -Werror -o build/testdoc test.c -lpthread

test1: test.c
	$(CC) -DTEST1 -Os -W -Wall -Werror -o build/test1 test.c -lpthread

test1b: test.c
	$(CC) -DTEST1B -Os -W -Wall -Werror -o build/test1b test.c

test2: test.c
	$(CC) -DTEST2 -Os -W -Wall -Werror -o build/test2 test.c -lpthread

test1-32: test.c
	$(CC) -m32 -DTEST1 -Os -W -Wall -Werror -o build/test1-32 test.c -lpthread

test2-32: test.c
	$(CC) -m32 -DTEST2 -Os -W -Wall -Werror -o build/test2-32 test.c -lpthread

sizes: sizes.c
	$(CC) -Os -W -Wall -Werror -o build/sizes sizes.c

sizes32: sizes.c
	$(CC) -m32 -Os -W -Wall -Werror -o build/sizes32 sizes.c

clean:
	rm -Rf build/*
