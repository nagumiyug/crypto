#include <stdint.h>
#include <wmmintrin.h>
#include <stdio.h>
#include "../inc/aes.h"


// AES轮常量
static const unsigned char Rcons[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};


/**
 * @brief Generate encryption subkeys
 * @param[in] key original key
 * @param[out] subKeys generated encryption subkeys
 * @return 0 OK
 * @return 1 Failed
 */
int aes_make_enc_subkeys(const unsigned char key[16], unsigned char subKeys[11][16]) {
    if (!key || !subKeys) {
        return 1; // 输入无效
    }
    __m128i round_keys[11];
    round_keys[0] = _mm_loadu_si128((__m128i *)key); // 加载初始密钥

    for (int i = 1; i <= 10; i++) {
        __m128i w4 = _mm_aeskeygenassist_si128(round_keys[i - 1], Rcons[i]);
        w4 = _mm_shuffle_epi32(w4, _MM_SHUFFLE(3, 3, 3, 3));
        __m128i w = _mm_xor_si128(round_keys[i-1], _mm_slli_si128(round_keys[i-1], 4));
        w = _mm_xor_si128(w, _mm_slli_si128(w, 4));
        w = _mm_xor_si128(w, _mm_slli_si128(w, 4));
        round_keys[i] = _mm_xor_si128(w, w4);
    }
    // 存储生成的轮密钥
    for (int i = 0; i < 11; i++) {
        _mm_storeu_si128((__m128i *)subKeys[i], round_keys[i]);
    }
    return 0; // 成功
}


/**
 * @brief Generate decryption subkeys
 * @param[in] key original key
 * @param[out] subKeys generated decryption subkeys
 * @return 0 OK
 * @return 1 Failed
 */
int aes_make_dec_subkeys(const unsigned char key[16], unsigned char subKeys[11][16]) {
    if (!key || !subKeys) {
        return 1; // 输入无效
    }
    
    __m128i round_keys[11];
    round_keys[0] = _mm_loadu_si128((__m128i *)key); // 加载初始密钥

    // 生成加密密钥的轮密钥
    for (int i = 1; i <= 10; i++) {
        __m128i w4 = _mm_aeskeygenassist_si128(round_keys[i - 1], Rcons[i]);
        w4 = _mm_shuffle_epi32(w4, _MM_SHUFFLE(3, 3, 3, 3));
        __m128i w = _mm_xor_si128(round_keys[i-1], _mm_slli_si128(round_keys[i-1], 4));
        w = _mm_xor_si128(w, _mm_slli_si128(w, 4));
        w = _mm_xor_si128(w, _mm_slli_si128(w, 4));
        round_keys[i] = _mm_xor_si128(w, w4);
    }
    for (int i = 1; i <= 9; i++) {
        round_keys[i] = _mm_aesimc_si128(round_keys[i]);
    }
    // 存储生成的轮密钥
    for (int i = 0; i < 11; i++) {
        _mm_storeu_si128((__m128i *)subKeys[i], round_keys[i]);
    }
    return 0;
}

/**
 * @brief AES encrypt single block
 * @param[in] input plaintext, [length = AES_BLOCK_SIZE]
 * @param[in] subKeys subKeys
 * @param[out] output ciphertext, [length = AES_BLOCK_SIZE]
 */
void aes_encrypt_block(const unsigned char *input, unsigned char subKeys[11][16], unsigned char *output) {
    __m128i state = _mm_loadu_si128((__m128i*)input);

    // 初始轮密钥加
    state = _mm_xor_si128(state, _mm_loadu_si128((__m128i*)subKeys[0]));
    
    // 1~9轮加密
    for (int round = 1; round < 10; ++round) {
        state = _mm_aesenc_si128(state, _mm_loadu_si128((__m128i*)subKeys[round]));
    }
    
    // 最后一轮加密
    state = _mm_aesenclast_si128(state, _mm_loadu_si128((__m128i*)subKeys[10]));
    
    // 将加密后的数据存储到输出
    _mm_storeu_si128((__m128i*)output, state);
}

/**
 * @brief AES decrypt single block
 * @param[in] input ciphertext, [length = AES_BLOCK_SIZE]
 * @param[in] subKeys subKeys
 * @param[out] output plaintext, [length = AES_BLOCK_SIZE]
 */
void aes_decrypt_block(const unsigned char *input, unsigned char subKeys[11][16], unsigned char *output) {
    __m128i state = _mm_loadu_si128((__m128i*)input);  // 将输入的密文数据块加载到128位寄存器中

    // 初始轮密钥加
    state = _mm_xor_si128(state, _mm_loadu_si128((__m128i*)subKeys[10]));
    
    // 1~9轮解密
    for (int round = 9; round >= 1; --round) {
        state = _mm_aesdec_si128(state, _mm_loadu_si128((__m128i*)subKeys[round]));
    }
    
    // 最后一轮解密
    state = _mm_aesdeclast_si128(state, _mm_loadu_si128((__m128i*)subKeys[0]));
    
    // 将解密后的数据存储到输出
    _mm_storeu_si128((__m128i*)output, state);
}