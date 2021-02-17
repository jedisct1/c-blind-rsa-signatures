all: test

test:
	$(CC) -Wall -Isrc -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -o test src/*.c -lcrypto
	./test
	