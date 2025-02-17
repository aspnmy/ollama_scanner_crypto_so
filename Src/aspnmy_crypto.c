#include "aspnmy_crypto.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

#define KEY_FILE ".crypto_key"
#define KEY_LENGTH 32
#define IV_LENGTH 16
#define BUFFER_SIZE 4096

// OpenSSL 初始化
void init_openssl(void) {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
}

// 加密函数
char* encrypt_text(const char* plaintext, const char* key) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return NULL;
    }

    unsigned char iv[IV_LENGTH];
    int outlen, tmplen;
    
    // 生成随机 IV
    if (!RAND_bytes(iv, IV_LENGTH)) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    // 分配输出缓冲区
    size_t textlen = strlen(plaintext);
    unsigned char* ciphertext = malloc(textlen + EVP_MAX_BLOCK_LENGTH + IV_LENGTH);
    if (!ciphertext) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    // 初始化加密
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }
    
    // 复制 IV 到输出的开头
    memcpy(ciphertext, iv, IV_LENGTH);
    
    // 加密数据
    if (!EVP_EncryptUpdate(ctx, ciphertext + IV_LENGTH, &outlen, 
                          (unsigned char*)plaintext, textlen) ||
        !EVP_EncryptFinal_ex(ctx, ciphertext + IV_LENGTH + outlen, &tmplen)) {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }
    
    // 清理加密上下文
    EVP_CIPHER_CTX_free(ctx);
    
    // Base64 编码结果
    char* result = malloc(BUFFER_SIZE);
    if (!result) {
        free(ciphertext);
        return NULL;
    }

    EVP_EncodeBlock((unsigned char*)result, ciphertext, outlen + tmplen + IV_LENGTH);
    free(ciphertext);
    
    return result;
}

// 解密函数
char* decrypt_text(const char* ciphertext, const char* key) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return strdup("ERROR: 无法创建加密上下文");
    }

    int outlen, tmplen;
    
    // Base64 解码
    size_t cipherlen = strlen(ciphertext);
    unsigned char* decoded = malloc(cipherlen);
    if (!decoded) {
        EVP_CIPHER_CTX_free(ctx);
        return strdup("ERROR: 内存分配失败");
    }

    EVP_DecodeBlock(decoded, (unsigned char*)ciphertext, cipherlen);
    
    // 提取 IV
    unsigned char iv[IV_LENGTH];
    memcpy(iv, decoded, IV_LENGTH);
    
    // 分配输出缓冲区
    unsigned char* plaintext = malloc(cipherlen);
    if (!plaintext) {
        EVP_CIPHER_CTX_free(ctx);
        free(decoded);
        return strdup("ERROR: 内存分配失败");
    }
    
    // 初始化解密
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)key, iv)) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        EVP_CIPHER_CTX_free(ctx);
        free(decoded);
        free(plaintext);
        size_t msg_len = strlen("ERROR: ") + strlen(err_buf) + 1;
        char* err_msg = malloc(msg_len);
        snprintf(err_msg, msg_len, "ERROR: %s", err_buf);
        return err_msg;
    }
    
    // 解密数据
    if (!EVP_DecryptUpdate(ctx, plaintext, &outlen, decoded + IV_LENGTH, cipherlen - IV_LENGTH) ||
        !EVP_DecryptFinal_ex(ctx, plaintext + outlen, &tmplen)) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        EVP_CIPHER_CTX_free(ctx);
        free(decoded);
        free(plaintext);
        size_t msg_len = strlen("ERROR: ") + strlen(err_buf) + 1;
        char* err_msg = malloc(msg_len);
        snprintf(err_msg, msg_len, "ERROR: %s", err_buf);
        return err_msg;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    free(decoded);
    
    plaintext[outlen + tmplen] = '\0';
    return (char*)plaintext;
}

// 生成随机密钥
char* generate_key(void) {
    unsigned char* key = malloc(KEY_LENGTH);
    if (!key) {
        return NULL;
    }

    if (!RAND_bytes(key, KEY_LENGTH)) {
        free(key);
        return NULL;
    }
    
    char* hex_key = malloc(KEY_LENGTH * 2 + 1);
    if (!hex_key) {
        free(key);
        return NULL;
    }

    for(int i = 0; i < KEY_LENGTH; i++) {
        sprintf(hex_key + (i * 2), "%02x", key[i]);
    }
    
    free(key);
    return hex_key;
}

// 读取密钥文件
char* read_key_file() {
    char key_path[1024];
    snprintf(key_path, sizeof(key_path), "%s/%s", getenv("HOME"), KEY_FILE);
    
    FILE* fp = fopen(key_path, "r");
    if (!fp) return NULL;
    
    char* key = malloc(KEY_LENGTH * 2 + 1);
    if (fgets(key, KEY_LENGTH * 2 + 1, fp) == NULL) {
        free(key);
        fclose(fp);
        return NULL;
    }
    
    fclose(fp);
    return key;
}

// 写入密钥文件
int write_key_file(const char* key) {
    char key_path[1024];
    snprintf(key_path, sizeof(key_path), "%s/%s", getenv("HOME"), KEY_FILE);
    
    FILE* fp = fopen(key_path, "w");
    if (!fp) return 0;
    
    fprintf(fp, "%s", key);
    fclose(fp);
    chmod(key_path, 0600);
    return 1;
}

void print_help() {
    printf("用法: aspnmy_crypto {encrypt|decrypt|genkey} [text]\n");
    printf("  encrypt [text] - 加密文本\n");
    printf("  decrypt [text] - 解密文本\n");
    printf("  genkey        - 生成新密钥\n");
}

int main(int argc, char *argv[]) {
    init_openssl();

    if (argc < 2) {
        print_help();
        return 1;
    }

    const char* command = argv[1];

    // 如果命令为 genkey，则生成并更新 key 文件（手工更新）
    if (strcmp(command, "genkey") == 0) {
        char* new_key = generate_key();
        if (new_key && write_key_file(new_key)) {
            printf("密钥已更新: %s\n", new_key);
            free(new_key);
            return 0;
        }
        return 1;
    }

    // 对于 encrypt 和 decrypt 命令，仅读取现有 key，不自动更新
    char* key = getenv("CRYPTO_KEY");
    if (!key) {
        key = read_key_file();
    }
    if (!key) {
        fprintf(stderr, "错误: 未找到密钥，请先运行 genkey 命令生成或更新密钥\n");
        return 1;
    }

    if (strcmp(command, "encrypt") == 0) {
        char input[BUFFER_SIZE];
        if (argc < 3) {
            printf("输入要加密的文本: ");
            if (!fgets(input, sizeof(input), stdin)) return 1;
            input[strcspn(input, "\n")] = 0;
        } else {
            strncpy(input, argv[2], sizeof(input) - 1);
        }
        
        char* result = encrypt_text(input, key);
        if (result) {
            printf("%s\n", result);
            free(result);
            return 0;
        }
        return 1;
    }

    if (strcmp(command, "decrypt") == 0) {
        char input[BUFFER_SIZE];
        if (argc < 3) {
            printf("输入要解密的文本: ");
            if (!fgets(input, sizeof(input), stdin)) return 1;
            input[strcspn(input, "\n")] = 0;
        } else {
            strncpy(input, argv[2], sizeof(input) - 1);
        }
        
        char* result = decrypt_text(input, key);
        if (result) {
            printf("%s\n", result);
            free(result);
            return 0;
        }
        return 1;
    }

    print_help();
    return 1;
}
