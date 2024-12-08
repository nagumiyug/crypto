#ifndef SM4_CBC_H
#define SM4_CBC_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "sm4.h"
#include <stdio.h>

void sm4_encrypt_cbc(const unsigned char *input, size_t blockCount, const unsigned char iv[SM4_BLOCK_SIZE], 
                    const uint32_t encSubKeys[SM4_ROUNDS], unsigned char *output);

void sm4_decrypt_cbc(const unsigned char *input, size_t blockCount, const unsigned char iv[SM4_BLOCK_SIZE], 
                    const uint32_t decSubKeys[SM4_ROUNDS], unsigned char *output);
// Correctness test function
void test_sm4_cbc_correctness(size_t blockCount);

#ifdef __cplusplus
}
#endif

#endif
