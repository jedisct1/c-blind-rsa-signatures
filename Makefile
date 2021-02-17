all: test

test: src/blind_rsa.c src/blind_rsa.h src/test.c
	$(CC) -Wall -Isrc -I/usr/local/opt/openssl/include -I/usr/local/include -L/usr/local/opt/openssl/lib -L/usr/local/lib -o test src/blind_rsa.c src/test.c -lcrypto
	./test
