#ifndef ASPNMY_CRYPTO_H
#define ASPNMY_CRYPTO_H

// OpenSSL 函数声明
void init_openssl(void);
char* generate_key(void);
char* encrypt_text(const char* plaintext, const char* key);
char* decrypt_text(const char* ciphertext, const char* key);

#endif // ASPNMY_CRYPTO_H
