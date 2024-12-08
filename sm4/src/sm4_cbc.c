#include "../inc/sm4_cbc.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
// CBC模式加密
void sm4_encrypt_cbc(const unsigned char *input, size_t blockCount, const unsigned char iv[SM4_BLOCK_SIZE], const uint32_t encSubKeys[SM4_ROUNDS], unsigned char *output) {
    if (!input || !iv || !encSubKeys || !output) {
        return ;
    }
    unsigned char curBlock[SM4_BLOCK_SIZE]; 
    unsigned char preBlock[SM4_BLOCK_SIZE];
    memcpy(preBlock, iv, SM4_BLOCK_SIZE); 
    for (size_t i = 0; i < blockCount; i++) {
        memcpy(curBlock, input + i * SM4_BLOCK_SIZE, SM4_BLOCK_SIZE);

        // 明文块与前一块密文异或
        for (size_t j = 0; j < SM4_BLOCK_SIZE; j++) {
            curBlock[j] ^= preBlock[j];
        }

        sm4_encrypt_block(curBlock, encSubKeys, output + i * SM4_BLOCK_SIZE);

        memcpy(preBlock, output + i * SM4_BLOCK_SIZE, SM4_BLOCK_SIZE);
    }

}
// CBC模式解密
void sm4_decrypt_cbc(const unsigned char *input, size_t blockCount, const unsigned char iv[SM4_BLOCK_SIZE], const uint32_t decSubKeys[SM4_ROUNDS], unsigned char *output) {
    if (!input || !iv || !decSubKeys || !output) {
        return ;
    }

    unsigned char currentBlock[SM4_BLOCK_SIZE];
    unsigned char previousBlock[SM4_BLOCK_SIZE];
    unsigned char decryptedBlock[SM4_BLOCK_SIZE]; 
    memcpy(previousBlock, iv, SM4_BLOCK_SIZE);
    
    for (size_t i = 0; i < blockCount; i++) {
        memcpy(currentBlock, input + i * SM4_BLOCK_SIZE, SM4_BLOCK_SIZE);

        sm4_decrypt_block(currentBlock, decSubKeys, decryptedBlock);

        // 解密后的结果与前一块密文异或得到明文
        for (size_t j = 0; j < SM4_BLOCK_SIZE; j++) {
            decryptedBlock[j] ^= previousBlock[j];
        }

        memcpy(output + i * SM4_BLOCK_SIZE, decryptedBlock, SM4_BLOCK_SIZE);

        memcpy(previousBlock, currentBlock, SM4_BLOCK_SIZE);
    }
}
// CBC模式正确性检验
void test_sm4_cbc_correctness(size_t blockCount) {
    srand((unsigned int)time(NULL));

    unsigned char key[SM4_KEY_SIZE], iv[SM4_BLOCK_SIZE];
    uint32_t encSubKeys[SM4_ROUNDS], decSubKeys[SM4_ROUNDS];
    // 生成密钥和iv
    for (int i = 0; i < SM4_KEY_SIZE; i++) {
        key[i] = rand() & 0xFF;
    }
    for (int i = 0; i < SM4_BLOCK_SIZE; i++) {
        iv[i] = rand() & 0xFF;
    }
    // 生成加密密钥和解密密钥
    if (sm4_make_enc_subkeys(key, encSubKeys) != 0) {
        printf("Failed to generate encryption subkeys.\n");
        return;
    }
    if (sm4_make_dec_subkeys(key, decSubKeys) != 0) {
        printf("Failed to generate decryption subkeys.\n");
        return;
    }

    size_t text_size = blockCount * SM4_BLOCK_SIZE;
    unsigned char *plaintext = (unsigned char *)malloc(text_size);
    unsigned char *ciphertext = (unsigned char *)malloc(text_size);
    unsigned char *decrypted = (unsigned char *)malloc(text_size);
    // 生成明文
    for (size_t i = 0; i < text_size; i++) {
        plaintext[i] = rand() & 0xFF;
    }

    sm4_encrypt_cbc(plaintext, blockCount, iv, encSubKeys, ciphertext);
    sm4_decrypt_cbc(ciphertext, blockCount, iv, decSubKeys, decrypted);
    
    // 比较解密结果和明文
    if (memcmp(plaintext, decrypted, text_size) == 0) {
        printf("SM4 CBC correctness test passed.\n");
    } else {
        printf("SM4 CBC correctness test failed.\n");
    }

    free(plaintext);
    free(ciphertext);
    free(decrypted);
}
// 随机生成加密密钥和iv
void encInitCBC(unsigned char key[SM4_KEY_SIZE], uint32_t encSubKeys[SM4_ROUNDS], unsigned char iv[SM4_BLOCK_SIZE]) {
    srand((unsigned int)time(NULL));
    for (int i = 0; i < SM4_KEY_SIZE; i++) {
        key[i] = rand() & 0xFF;
    }
    for (int i = 0; i < SM4_BLOCK_SIZE; i++) {
        iv[i] = rand() & 0xFF;
    }
    if (sm4_make_enc_subkeys(key, encSubKeys) != 0)
    {
        printf("Failed to generate encryption subkeys.\n");
        return;
    }
}
// 随机生成解密密钥和iv
void decInitCBC(unsigned char key[SM4_KEY_SIZE], uint32_t decSubKeys[SM4_ROUNDS], unsigned char iv[SM4_BLOCK_SIZE]) {
    srand((unsigned int)time(NULL));
    for (int i = 0; i < SM4_KEY_SIZE; i++) {
        key[i] = rand() & 0xFF;
    }
    for (int i = 0; i < SM4_BLOCK_SIZE; i++) {
        iv[i] = rand() & 0xFF;
    }
    if (sm4_make_dec_subkeys(key, decSubKeys) != 0)
    {
        printf("Failed to generate decryption subkeys.\n");
        return;
    }
}
// CBC模式加解密性能检验
void test_sm4_cbc_performance(size_t blockCount, int iterations) {
    srand((unsigned int)time(NULL));

    unsigned char key[SM4_KEY_SIZE], iv[SM4_BLOCK_SIZE];
    uint32_t encSubKeys[SM4_ROUNDS], decSubKeys[SM4_ROUNDS];
    
    for (int i = 0; i < SM4_KEY_SIZE; i++) {
        key[i] = rand() & 0xFF;
    }
    for (int i = 0; i < SM4_BLOCK_SIZE; i++) {
        iv[i] = rand() & 0xFF;
    }
    
    if (sm4_make_enc_subkeys(key, encSubKeys) != 0) {
        printf("Failed to generate encryption subkeys.\n");
        return;
    }
    if (sm4_make_dec_subkeys(key, decSubKeys) != 0) {
        printf("Failed to generate decryption subkeys.\n");
        return;
    }

    size_t text_size = blockCount * SM4_BLOCK_SIZE;
    unsigned char *plaintext = (unsigned char *)malloc(text_size);
    unsigned char *ciphertext = (unsigned char *)malloc(text_size);
    unsigned char *decrypted = (unsigned char *)malloc(text_size);

    for (size_t i = 0; i < text_size; i++) {
        plaintext[i] = rand() & 0xFF;
    }

    sm4_encrypt_cbc(plaintext, blockCount, iv, encSubKeys, ciphertext);
    sm4_decrypt_cbc(ciphertext, blockCount, iv, decSubKeys, decrypted);

    // 加密的平均时间
    double enc_total_time = 0.0;
    for (int i = 0; i < iterations; i++) {
        encInitCBC(key, encSubKeys, iv);
        clock_t start_time = clock();
        sm4_encrypt_cbc(ciphertext, blockCount, iv, encSubKeys, ciphertext);
        clock_t end_time = clock();
        enc_total_time += (double)(end_time - start_time) / CLOCKS_PER_SEC;
    }
    double enc_time = enc_total_time / iterations;
    printf("SM4-CBC average encryption time for %zuB over %d iterations: %f seconds.\n", blockCount * SM4_BLOCK_SIZE, iterations, enc_time);
    // 解密的平均时间
    double dec_total_time = 0.0;
    for (int i = 0; i < iterations; i++) {
        decInitCBC(key, decSubKeys, iv);
        clock_t start_time = clock();
        sm4_decrypt_cbc(decrypted, blockCount, iv, decSubKeys, decrypted);
        clock_t end_time = clock();
        dec_total_time += (double)(end_time - start_time) / CLOCKS_PER_SEC;
    }
    double dec_time = dec_total_time / iterations;
    printf("SM4-CBC average decryption time for %zuB over %d iterations: %f seconds.\n", blockCount * SM4_BLOCK_SIZE, iterations, dec_time);

    free(plaintext);
    free(ciphertext);
    free(decrypted);
}