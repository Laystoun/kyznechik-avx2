#include "kyznechik.h"
#include <iostream>
#include <algorithm>
#include <random>
#include <emmintrin.h>
#include <immintrin.h>

void Kyznechik::S_transformation(uint8_t *p_inf) {
    for (int i = 0; i < 16; i++) p_inf[i] = S[p_inf[i]];
}

void Kyznechik::S_transformation_inv(uint8_t *p_inf) {
    for (int i = 0; i < 16; i++) p_inf[i] = IS[p_inf[i]];
}

void Kyznechik::R_transformation(uint8_t *p_inf) {
    uint8_t x = 0;
    for (int i = 0; i < 16; i++)
        x ^= L_COEFFS[i][p_inf[i]];
    
    for (int i = 15; i > 0; i--) p_inf[i] = p_inf[i - 1];
    
    p_inf[0] = x;
}

void Kyznechik::L_transformation(uint8_t *p_inf) {
    for (int i = 0; i < 16; i++) R_transformation(p_inf);
}

void Kyznechik::expand_keys() {
    std::copy(master_key, master_key + 16, ROUND_KEYS[0].begin());
    std::copy(master_key + 16, master_key + 32, ROUND_KEYS[1].begin());

    r_key k1 = ROUND_KEYS[0];
    r_key k2 = ROUND_KEYS[1];
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            r_key temp = k1;

            for (int k = 0; k < 16; k++) k1[k] ^= ITER_CONSTANTS[i * 8 + j][k];

            S_transformation(k1.data());
            L_transformation(k1.data());

            for (int k = 0; k < 16; k++) k1[k] ^= k2[k];

            k2 = temp;
        }
        ROUND_KEYS[2 * i + 2] = k1; ROUND_KEYS[2 * i + 3] = k2;
    }
}

void Kyznechik::encrypt_block(uint8_t *p_inf) {
    #ifdef __AVX2__
        __m256i b0 = _mm256_loadu_si256((__m256i*)(p_inf + 0));
        __m256i b1 = _mm256_loadu_si256((__m256i*)(p_inf + 32));
        __m256i b2 = _mm256_loadu_si256((__m256i*)(p_inf + 64));
        __m256i b3 = _mm256_loadu_si256((__m256i*)(p_inf + 96));

        for (int i = 0; i < 9; i++) {
            __m128i k128 = _mm_loadu_si128((__m128i*)ROUND_KEYS[i].data());
            __m256i key = _mm256_set_m128i(k128, k128);

            b0 = _mm256_xor_si256(b0, key);
            b1 = _mm256_xor_si256(b1, key);
            b2 = _mm256_xor_si256(key, b2);
            b3 = _mm256_xor_si256(key, b3);

            alignas(32) uint8_t t[8][16];
            _mm256_storeu_si256((__m256i*)t[0], b0);
            _mm256_storeu_si256((__m256i*)t[2], b1);
            _mm256_storeu_si256((__m256i*)t[4], b2);
            _mm256_storeu_si256((__m256i*)t[6], b3);

            b0 = _mm256_setzero_si256();
            b1 = _mm256_setzero_si256();
            b2 = _mm256_setzero_si256();
            b3 = _mm256_setzero_si256();

            for (int x = 0; x < 16; x++)
            {
                b0 = _mm256_xor_si256(b0, _mm256_set_m128i(
                    _mm_loadu_si128((__m128i*)LS_TABLE[x][t[1][x]].data()),
                    _mm_loadu_si128((__m128i*)LS_TABLE[x][t[0][x]].data())
                ));

                b1 = _mm256_xor_si256(b1, _mm256_set_m128i(
                    _mm_loadu_si128((__m128i*)LS_TABLE[x][t[3][x]].data()),
                    _mm_loadu_si128((__m128i*)LS_TABLE[x][t[2][x]].data())
                ));

                b2 = _mm256_xor_si256(b2, _mm256_set_m128i(
                    _mm_loadu_si128((__m128i*)LS_TABLE[x][t[5][x]].data()),
                    _mm_loadu_si128((__m128i*)LS_TABLE[x][t[4][x]].data())
                ));

                b3 = _mm256_xor_si256(b3, _mm256_set_m128i(
                    _mm_loadu_si128((__m128i*)LS_TABLE[x][t[7][x]].data()),
                    _mm_loadu_si128((__m128i*)LS_TABLE[x][t[6][x]].data())
                ));
            }
        }

        __m128i l_k128 = _mm_loadu_si128((__m128i *)ROUND_KEYS[9].data());
        __m256i l_k256 = _mm256_set_m128i(l_k128, l_k128);

        b0 = _mm256_xor_si256(b0, l_k256); _mm256_storeu_si256((__m256i*)(p_inf + 0), b0);
        b1 = _mm256_xor_si256(b1, l_k256); _mm256_storeu_si256((__m256i*)(p_inf + 32), b1);
        b2 = _mm256_xor_si256(b2, l_k256); _mm256_storeu_si256((__m256i*)(p_inf + 64), b2);
        b3 = _mm256_xor_si256(b3, l_k256); _mm256_storeu_si256((__m256i*)(p_inf + 96), b3);
    #else
        // Обрабатываем 8 блоков по 16 байт обычным циклом
        uint8_t state[8][16];
        for (int b = 0; b < 8; b++)
            memcpy(state[b], p_inf + b * 16, 16);

        for (int i = 0; i < 9; i++) {
            const uint8_t* key = ROUND_KEYS[i].data();

            for (int b = 0; b < 8; b++)
                for (int j = 0; j < 16; j++)
                    state[b][j] ^= key[j];

            uint8_t next[8][16] = {};
            for (int b = 0; b < 8; b++)
                for (int x = 0; x < 16; x++) {
                    const uint8_t* ls = LS_TABLE[x][state[b][x]].data();
                    for (int j = 0; j < 16; j++)
                        next[b][j] ^= ls[j];
                }

            memcpy(state, next, sizeof(state));
        }

        const uint8_t* last_key = ROUND_KEYS[9].data();
        for (int b = 0; b < 8; b++) {
            for (int j = 0; j < 16; j++)
                state[b][j] ^= last_key[j];
            memcpy(p_inf + b * 16, state[b], 16);
        }
    #endif
}

void Kyznechik::init() {
    for (int i = 0; i < 32; i++) {
        std::array<uint8_t, 16> temp_c{0};
        temp_c[15] = (uint8_t)(i + 1);
        L_transformation(temp_c.data());
        ITER_CONSTANTS[i] = temp_c;
    }

    expand_keys();
}

void Kyznechik::L_tranformation_inv(uint8_t *p_inf) {
    for (int i = 0; i < 16; i++) {
        R_transformation_inv(p_inf);
    }
}

void Kyznechik::R_transformation_inv(uint8_t *p_inf) {
    uint8_t x = p_inf[0];

    for (int i = 0; i < 15; i++) p_inf[i] = p_inf[i + 1];

    p_inf[15] = x;

    uint8_t sum = 0;
    for (int i = 0; i < 16; i++) sum ^= L_COEFFS[i][p_inf[i]];

    p_inf[15] = sum;
}

void Kyznechik::decrypt_block(uint8_t *p_inf) {
#ifdef __AVX2__
    __m256i b1 = _mm256_loadu_si256((__m256i*)(p_inf + 0));
    __m256i b2 = _mm256_loadu_si256((__m256i*)(p_inf + 32));
    __m256i b3 = _mm256_loadu_si256((__m256i*)(p_inf + 64));
    __m256i b4 = _mm256_loadu_si256((__m256i*)(p_inf + 96));

    __m128i k128 = _mm_loadu_si128((__m128i*)ROUND_KEYS[9].data());
    __m256i key = _mm256_set_m128i(k128, k128);

    b1 = _mm256_xor_si256(b1, key);
    b2 = _mm256_xor_si256(b2, key);
    b3 = _mm256_xor_si256(b3, key);
    b4 = _mm256_xor_si256(b4, key);

    _mm256_storeu_si256((__m256i*)p_inf, b1);
    _mm256_storeu_si256((__m256i*)(p_inf + 32), b2);
    _mm256_storeu_si256((__m256i*)(p_inf + 64), b3);
    _mm256_storeu_si256((__m256i*)(p_inf + 96), b4);
#else
    const uint8_t* key9 = ROUND_KEYS[9].data();
    for (int b = 0; b < 8; b++)
        for (int j = 0; j < 16; j++)
            p_inf[b * 16 + j] ^= key9[j];
#endif

    for (int i = 8; i >= 0; i--) {
        for (int b = 0; b < 8; b++) {
            uint8_t *blk = p_inf + b * 16;
            L_tranformation_inv(blk);
            S_transformation_inv(blk);

#ifdef __AVX2__
            __m128i block = _mm_loadu_si128((__m128i*)blk);
            __m128i rkey = _mm_loadu_si128((__m128i*)ROUND_KEYS[i].data());
            block = _mm_xor_si128(block, rkey);
            _mm_storeu_si128((__m128i*)blk, block);
#else
            const uint8_t* rkey = ROUND_KEYS[i].data();
            for (int j = 0; j < 16; j++)
                blk[j] ^= rkey[j];
#endif
        }
    }
}