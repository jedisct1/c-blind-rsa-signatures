all: test_blind_rsa

test_blind_rsa: src/blind_rsa.c src/blind_rsa.h src/test_blind_rsa.c
	$(CC) -Wall -Isrc -I/opt/homebrew/opt/openssl@3/include -I/usr/local/opt/openssl@3/include -I/usr/local/include -L/opt/homebrew/opt/openssl@3/lib -L/usr/local/opt/openssl@3/lib -L/usr/local/lib -o test src/blind_rsa.c src/test_blind_rsa.c -lcrypto
	./test
