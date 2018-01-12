# [dep] : OpenSSL 1.0.1t
gcc -o checkpass getfvek.c -lssl -lcrypto
gcc -o getvmkdatum getvmk.c
