#include "../inc/sm4_cbc.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
void sm4_encrypt_cbc(const unsigned char *input, size_t blockCount, const unsigned char iv[SM4_BLOCK_SIZE], const uint32_t encSubKeys[SM4_ROUNDS], unsigned char *output) {
    if (!input || !iv || !encSubKeys || !output) {
        return ;
    }
    unsigned char curBlock[SM4_BLOCK_SIZE]; 
    unsigned char preBlock[SM4_BLOCK_SIZE];
    memcpy(preBlock, iv, SM4_BLOCK_SIZE); 
    for (size_t i = 0; i < blockCount; i++) {
        memcpy(curBlock, input + i * SM4_BLOCK_SIZE, SM4_BLOCK_SIZE);

        // 明文块与前一块密文（或IV）异或
        for (size_t j = 0; j < SM4_BLOCK_SIZE; j++) {
            curBlock[j] ^= preBlock[j];
        }

        sm4_encrypt_block(curBlock, encSubKeys, output + i * SM4_BLOCK_SIZE);

        memcpy(preBlock, output + i * SM4_BLOCK_SIZE, SM4_BLOCK_SIZE);
    }

}

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

        // 解密后的结果与前一块密文（或IV）异或得到明文
        for (size_t j = 0; j < SM4_BLOCK_SIZE; j++) {
            decryptedBlock[j] ^= previousBlock[j];
        }

        memcpy(output + i * SM4_BLOCK_SIZE, decryptedBlock, SM4_BLOCK_SIZE);

        memcpy(previousBlock, currentBlock, SM4_BLOCK_SIZE);
    }
}

// Correctness test function
void test_sm4_cbc_correctness(size_t blockCount) {
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
    
    if (memcmp(plaintext, decrypted, text_size) == 0) {
        printf("SM4 CBC correctness test passed.\n");
    } else {
        printf("SM4 CBC correctness test failed.\n");
    }

    free(plaintext);
    free(ciphertext);
    free(decrypted);
}