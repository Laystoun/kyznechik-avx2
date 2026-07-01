#include <iostream>
#include <iomanip>

#include "key_utils.h"
#include "SHA256.h"

void print_rounded_keys(Kyznechik& kyz) {
        
        std::wcout << "MASTER KEY: ";
        for (int m_key = 0; m_key < 32; m_key++) {
            std::wcout << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<int>(kyz.master_key[m_key]);
        }
        std::wcout << std::endl << std::endl;
    
        std::wcout << "Rounded keys: \n"
                   << std::endl;

        for (int i = 0; i < 10; i++)
        {
            std::wcout << i << ": ";
            for (int j = 0; j < 16; j++)
            {
                std::wcout << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<int>(kyz.ROUND_KEYS[i][j]);
            }
            std::wcout << std::endl;
        }
        std::wcout << std::endl;
}

void key_finger_print(std::array<std::array<uint8_t, 16ULL>, 10ULL>& ROUND_KEY) {
    SHA256 sha;
    const wchar_t* SHADE[] = {
        L" ",        // 0x00–0x1F
        L"░",        // 0x20–0x5F
        L"▒",        // 0x60–0x9F
        L"▓",        // 0xA0–0xDF
        L"█"         // 0xE0–0xFF
    };
    
    const size_t ROUND_KEY_SIZE = 160;
    
    uint8_t key_linear[ROUND_KEY_SIZE];
    for (int r_key = 0; r_key < 10; r_key++) {
        for (int key_v = 0; key_v < 16; key_v++) {
            key_linear[r_key * 16 + key_v] = ROUND_KEY[r_key][key_v];       
        }
    }
    
    sha.update(key_linear, 160);

    std::array<uint8_t, 32> key_hash = sha.digest();
    std::array<uint8_t, 96 + 32> expand_fingerprint;

    for (int f_hash = 0; f_hash < 32; f_hash++) {
        expand_fingerprint[f_hash] = key_hash[f_hash];
    }

    for (int ex = 1; ex < 4; ex++) {
        int rotr = (key_hash[ex] >> 4) & 0x0F;
        uint8_t rotl_res = (uint8_t)((key_hash[ex] & 0x0F) ^ rotr);

        sha.update(&rotl_res, 1);

        std::array<uint8_t, 32> bit_hash = sha.digest();

        for (int dec = 0; dec < 32; dec++)
            expand_fingerprint[32 * ex + dec] = bit_hash[dec];
    }

    std::wcout << "KEY FINGERPRINT (SHA-256):" << std::endl << std::endl;
    for(int key_c = 0; key_c < 128; key_c++) {
        uint8_t hex_v = expand_fingerprint[key_c];
        if (hex_v >= 0x00 && hex_v <= 0x1F) std::wcout << SHADE[0];
        if (hex_v <= 0x5F && hex_v >= 0x20) std::wcout << SHADE[1];
        if (hex_v >= 0x60 && hex_v <= 0x9F) std::wcout << SHADE[2];
        if (hex_v <= 0xDF && hex_v >= 0xA0) std::wcout << SHADE[3];
        if (hex_v >= 0xE0 && hex_v <= 0xFF) std::wcout << SHADE[4];

        if ((key_c + 1) % 16 == 0) std::wcout << std::endl;
    }
    std::wcout << std::endl;
}

void create_pbkdf_password(Kyznechik& kyz, bool is_decrypt) {
    std::array<uint8_t, 32> this_hash = {0};
    std::wcout << "Password: ";
    std::wstring wpassword;
    std::getline(std::wcin, wpassword);

    std::string password (wpassword.begin(), wpassword.end());
    if (is_decrypt) {
        std::wcout << "Hashing password and salt (PIM => 500.000 iterations)" << std::endl;
        
        SHA256 sha;
        for (int i = 0; i < 500000; i++) {
            if (i == 0) {
                sha.update(password);
            } else {
                std::string this_hex = SHA256::toString(this_hash);
                sha.update(this_hex);
            }
            this_hash = sha.digest();
        }
        for (int f_key = 0; f_key < 32; f_key++) {
            kyz.master_key[f_key] = this_hash[f_key];
        }
        kyz.init();
        key_finger_print(kyz.ROUND_KEYS);
        
        std::wcin.ignore(1, L'\n');

        return;
    } else {
        SHA256 sha;
        std::string d_pass {password.begin(), password.end()};
        
        std::wcout << "Hashing password and salt (PIM => 500.000 iterations)" << std::endl;
        for (int h = 0; h < 500000; h++) {
            if (h == 0) {
                sha.update(d_pass);
            } else {
                std::string this_hex = SHA256::toString(this_hash);
                sha.update(this_hex);
            }
            this_hash = sha.digest();
        }
        for (int m_key = 0; m_key < 32; m_key++) {
            kyz.master_key[m_key] = this_hash[m_key];
        }

        kyz.init();
        key_finger_print(kyz.ROUND_KEYS);

        std::wcout << "Save for decrypt: " << wpassword;
        std::wcout << std::endl << std::endl;

        std::wcin.ignore(1, L'\n');
    }
}