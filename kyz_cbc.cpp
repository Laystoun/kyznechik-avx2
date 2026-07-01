#include <emmintrin.h>
#include <immintrin.h>
#include <sodium.h>

#include "kyznechik.h"

void Kyznechik::cbc_generate_iv() {
    randombytes_buf(cbc_prev_block, sizeof(cbc_prev_block));
}

void Kyznechik::cbc_set_iv(const uint8_t* iv) {
    memcpy(cbc_prev_block, iv, sizeof(cbc_prev_block));
}

void Kyznechik::cbc_encrypt_block(uint8_t *p_inf) {
    for(int i = 0; i < 16; i++) {
        p_inf[i] ^= cbc_prev_block[i];
    }
    encrypt_block(p_inf);

    memcpy(cbc_prev_block, p_inf, sizeof(cbc_prev_block));
}

void Kyznechik::cbc_decrypt_block(uint8_t *p_inf) {
    uint8_t next_block[16]; memcpy(next_block, p_inf, sizeof(next_block));
    decrypt_block(p_inf);
    for(int i = 0; i < 16; i++) {
        p_inf[i] ^= cbc_prev_block[i];
    } memcpy(cbc_prev_block, next_block, sizeof(cbc_prev_block));
}