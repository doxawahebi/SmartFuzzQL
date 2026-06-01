CC ?= gcc
CFLAGS ?= -Wall -Wextra -g

all: sample-vuln

sample-vuln: src/main.o src/vuln.o
	$(CC) $(CFLAGS) -o $@ $^

src/main.o: src/main.c include/vuln.h
	$(CC) $(CFLAGS) -Iinclude -c -o $@ src/main.c

src/vuln.o: src/vuln.c include/vuln.h
	$(CC) $(CFLAGS) -Iinclude -c -o $@ src/vuln.c

clean:
	rm -f sample-vuln src/*.o
