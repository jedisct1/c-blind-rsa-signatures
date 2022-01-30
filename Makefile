all: test

test: src/blind_rsa.c src/blind_rsa.h src/test.c
	$(CC) -Wall -Isrc -I/opt/homebrew/opt/openssl@3/include -I/usr/local/opt/openssl@3/include -I/usr/local/include -L/opt/homebrew/opt/openssl@3/lib -L/usr/local/opt/openssl@3/lib -L/usr/local/lib -o test src/blind_rsa.c src/test.c -lcrypto
	./test
