#include <filesystem>
#include <iostream>
#include <cwctype>
#include <algorithm>e

#include "cli.h"
#include "crypto_io.h"
#include "key_utils.h"

int handle_drop(Kyznechik& kyz, wchar_t* dropped_path) {
    std::wstring drop_logs;
    std::wcout << "With logs? (Y/N): ";
    bool is_logs = false;
    std::transform(drop_logs.begin(), drop_logs.end(), drop_logs.begin(), [](wchar_t c) { return std::towlower(c); });
    is_logs = (drop_logs == L"y" ? true : false);
    std::filesystem::path drop_path(dropped_path);
    if(!std::filesystem::exists(drop_path)) {
        std::cout << "Path don't exists...";
        return -1;
    }
    if(std::filesystem::is_directory(drop_path)) {
        if(is_logs) {
            create_pbkdf_password(kyz, false);
            print_rounded_keys(kyz);
            encrypt_directory<true>(kyz, drop_path.wstring());
        } else {
            create_pbkdf_password(kyz, false);
            std::wcout << "Start encrypt...\n";
            encrypt_directory<false>(kyz, drop_path.wstring());
            std::wcout << "Encrypt end. Close program";
        }
    } else if (std::filesystem::is_regular_file(drop_path)) {
        if(is_logs) {
            create_pbkdf_password(kyz, false);
            print_rounded_keys(kyz);
            std::wcout << "Start encrypt file...\n";
            encrypt_file<true>(kyz, drop_path.wstring());
            std::wcout << "End encrypt... Close program.";
        } else {
            create_pbkdf_password(kyz, false);
            std::wcout << "Start encrypt file...\n";
            encrypt_file<false>(kyz, drop_path.wstring());
            std::wcout << "End encrypt file. Close program.";
        }
    }
}

int handle_menu(Kyznechik& kyz) {
    std::wstring select;
    std::wcout << L"<=== ENCRYPT ===>\n\n1. File\n2. Directory\n\n<=== DECRYPT ===>\n\n3. File\n4. Directory\n\n( 1/2/3/4 ): ";
    std::getline(std::wcin, select);
    std::wcin.ignore(1, L'\n');
    if (select == L"1")
    {
        create_pbkdf_password(kyz, false);
        //print_rounded_keys(kyz);
        
        encrypt_file<true>(kyz);
    }
    if (select == L"2")
    {
        create_pbkdf_password(kyz, false);
        //print_rounded_keys(kyz);
        encrypt_directory<true>(kyz);
    }
    if (select == L"3")
    {
        create_pbkdf_password(kyz, true);
        //print_rounded_keys(kyz);
        decrypt_file<true>(kyz);
    }
    if (select == L"4")
    {
        create_pbkdf_password(kyz, true);
        //print_rounded_keys(kyz);
        decrypt_directory<true>(kyz);
    }
}

int run_cli(int argc, wchar_t* argv[]) {
    Kyznechik kyz;
    
    if (argc > 1) {
        return handle_drop(kyz, argv[1]); 
    }
    return handle_menu(kyz);
}