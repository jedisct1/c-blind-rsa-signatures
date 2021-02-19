.PHONY: all clean
all: test test2

clean:
	rm -f test test2

test: src/blind_rsa.c src/blind_rsa.h src/test.c
	$(CC) -Wall -Isrc -I/usr/local/opt/openssl/include -I/usr/local/include -L/usr/local/opt/openssl/lib -L/usr/local/lib -o test src/blind_rsa.c src/test.c -lcrypto
	./test

test2: src/blind_rsa.c src/blind_rsa.h src/test2.c
	$(CC) -Wall -Isrc -I/usr/local/opt/openssl/include -I/usr/local/include -L/usr/local/opt/openssl/lib -L/usr/local/lib -o test2 src/blind_rsa.c src/test2.c -lcrypto
	./test2
