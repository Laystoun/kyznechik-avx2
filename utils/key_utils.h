#ifndef KEY_UTILS_H
#define KEY_UTLIS_H

#include <array>
#include <cstdint>

#include "kyznechik.h"

void print_rounded_keys(Kyznechik& kyz);
void key_finger_print(std::array<std::array<uint8_t, 16ULL>, 10ULL>& ROUND_KEY);
void create_pbkdf_password(Kyznechik& kyz, bool is_decrypt);

#endif