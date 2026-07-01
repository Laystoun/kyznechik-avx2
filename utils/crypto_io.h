#include <string>
#include <cassert>
#include <vector>
#include <fstream>

#include "kyznechik.h"
#include "pkcs.h"

#ifndef CRYPTO_IO_H
#define CRYPTO_IO_H

template <bool with_logs>
void encrypt_file(Kyznechik &kyz, std::wstring drop_path = L"-1")
{
    std::wstring path;
    std::filesystem::path correct_path;

    if (drop_path == L"-1") {
        std::wcout << "enter PATH #: ";
        std::getline(std::wcin, path);
        correct_path = std::filesystem::path(path);
    } else {
        correct_path = drop_path;
    }

    {
        std::ifstream in{correct_path, std::ios::binary};

        std::filesystem::path outpath = std::filesystem::path(correct_path);
        outpath += L".enc";
        std::fstream out{outpath, std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc};
        assert(in && "In file not found");
        
        std::wcout << "Start encrypt...\n";

        std::vector<uint8_t> buffer(256 * 1024 * 1024);

        double total_sec_time;
        std::chrono::duration<double> total_encrypted_time;
        double encrypted_bytes_handl;
        std::chrono::high_resolution_clock::time_point start_program;
        std::chrono::high_resolution_clock::time_point start;

        if constexpr (with_logs)
        {
            total_sec_time = 0;
            total_encrypted_time = std::chrono::duration<double>::zero();
            encrypted_bytes_handl = 0;
            start_program = std::chrono::high_resolution_clock::now();
        }

        while (in.read(reinterpret_cast<char *>(buffer.data()), buffer.size()) || in.gcount() > 0)
        {
            size_t read_bytes = in.gcount();

            if (in.eof())
            {
                buffer.resize(read_bytes);
                pkcspad(buffer);
                read_bytes = buffer.size();
            }

            if constexpr (with_logs)
            {
                start = std::chrono::high_resolution_clock::now();
            }
#pragma omp parallel for
            for (size_t i = 0; i < read_bytes; i += 128)
            {
                kyz.encrypt_block(buffer.data() + i);
            }

            if constexpr (with_logs)
            {
                auto end = std::chrono::high_resolution_clock::now();
                total_encrypted_time += (end - start);
                encrypted_bytes_handl += read_bytes;
            }

            out.write(reinterpret_cast<char *>(buffer.data()), read_bytes);
        }

        in.close();
        out.close();
        std::filesystem::remove(correct_path);

        if constexpr (with_logs)
        {
            auto end_program = std::chrono::high_resolution_clock::now();

            std::chrono::duration<double> total_program_time = end_program - start_program;
            std::wcout << "Program time (s): " << total_program_time.count() << std::endl
                       << "Encrypted SPEED MB/s: " << (encrypted_bytes_handl / (1024 * 1024)) / total_encrypted_time.count() << std::endl
                       << "Encrypted TIME (s): " << total_encrypted_time.count() << std::endl;
        }

        std::wcout << "Directory success encrypted. Close program.\n";
    }
}

template <bool with_logs>
void encrypt_directory(Kyznechik &kyz, std::wstring drop_path = L"-1")
{
    std::filesystem::path correct_path;

    if(drop_path == L"-1") {
        std::wcout << "enter DIRECTORY #: ";
        std::wstring directory;
        std::getline(std::wcin, directory);
        correct_path = std::filesystem::path(directory);
    } else {
        correct_path = drop_path;
    }

    double total_sec_time;
    std::chrono::duration<double> total_encrypted_time;
    double encrypted_bytes_handl;
    std::chrono::high_resolution_clock::time_point start_program;
    std::chrono::high_resolution_clock::time_point start;

    if constexpr (with_logs)
    {
        total_sec_time = 0;
        total_encrypted_time = std::chrono::duration<double>::zero();
        encrypted_bytes_handl = 0;
        start_program = std::chrono::high_resolution_clock::now();
    }
    std::wcout << "Start encrypt...\n";
    for (auto &path : std::filesystem::recursive_directory_iterator(correct_path))
    {
        if (path.is_regular_file() && path.path().extension() != ".enc")
        {
            if constexpr (with_logs)
            {
                start_program = std::chrono::high_resolution_clock::now();
            }

            std::ifstream this_file(path.path(), std::ios::binary);
            std::ofstream out(path.path().parent_path() /= path.path().filename() += ".enc", std::ios::binary);

            assert(this_file && "Error open file...");

            std::vector<uint8_t> buffer(256 * 1024 * 1024);

            while (this_file.read(reinterpret_cast<char *>(buffer.data()), buffer.size()) || this_file.gcount() > 0)
            {
                size_t read_bytes = this_file.gcount();

                if (this_file.eof())
                {
                    buffer.resize(read_bytes);
                    pkcspad(buffer);
                    read_bytes = buffer.size();
                }

                if constexpr (with_logs)
                {
                    start = std::chrono::high_resolution_clock::now();
                }

                #pragma omp parallel for
                for (size_t i = 0; i < read_bytes; i += 128)
                {
                    kyz.encrypt_block(buffer.data() + i);
                }

                if constexpr (with_logs)
                {
                    std::wcout << "has been encrypted: " << path.path() << std::endl;
                }

                if constexpr (with_logs)
                {
                    auto end = std::chrono::high_resolution_clock::now();
                    total_encrypted_time += (end - start);
                    encrypted_bytes_handl += read_bytes;
                }

                out.write(reinterpret_cast<char *>(buffer.data()), read_bytes);    
            }
            this_file.close();
            out.close();
            std::filesystem::remove(path.path());
        }
    }

    if constexpr (with_logs)
    {
        auto end_program = std::chrono::high_resolution_clock::now();

        std::chrono::duration<double> total_program_time = end_program - start_program;
        std::wcout << "Program time (s): " << total_program_time.count() << std::endl
                   << "Encrypted SPEED MB/s: " << (encrypted_bytes_handl / (1024 * 1024)) / total_encrypted_time.count() << std::endl
                   << "Encrypted TIME (s): " << total_encrypted_time.count() << std::endl;
    }
    std::wcout << "Directory success encrypted. Close program.\n";
}

template <bool with_logs>
void decrypt_file(Kyznechik& kyz, std::wstring drop_path = L"-1") {
    std::wstring path;
    std::filesystem::path correct_path;

    if (drop_path == L"-1") {
        std::wcout << "enter PATH #: ";
        std::getline(std::wcin, path);
        correct_path = std::filesystem::path(path);
    } else {
        correct_path = drop_path;
    }

    {
        std::ifstream in{correct_path, std::ios::binary};

        std::filesystem::path outpath = std::filesystem::path(correct_path).replace_extension();
        std::fstream out{outpath, std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc};
        assert(in && "In file not found");
        
        std::wcout << "Start decrypt...\n";

        std::vector<uint8_t> buffer(256 * 1024 * 1024);

        double total_sec_time;
        std::chrono::duration<double> total_encrypted_time;
        double encrypted_bytes_handl;
        std::chrono::high_resolution_clock::time_point start_program;
        std::chrono::high_resolution_clock::time_point start;

        if constexpr (with_logs)
        {
            total_sec_time = 0;
            total_encrypted_time = std::chrono::duration<double>::zero();
            encrypted_bytes_handl = 0;
            start_program = std::chrono::high_resolution_clock::now();
        }

        while (in.read(reinterpret_cast<char *>(buffer.data()), buffer.size()) || in.gcount() > 0)
        {
            size_t read_bytes = in.gcount();

            bool is_last = in.eof();

            if constexpr (with_logs)
            {
                start = std::chrono::high_resolution_clock::now();
            }
#pragma omp parallel for
            for (size_t i = 0; i < read_bytes; i += 128)
            {
                kyz.decrypt_block(buffer.data() + i);
            }

            if (is_last)
            {
                buffer.resize(read_bytes);
                pkcsunpad(buffer);
                read_bytes = buffer.size();
            }

            if constexpr (with_logs)
            {
                auto end = std::chrono::high_resolution_clock::now();
                total_encrypted_time += (end - start);
                encrypted_bytes_handl += read_bytes;
            }

            out.write(reinterpret_cast<char *>(buffer.data()), read_bytes);
        }

        in.close();
        out.close();
        std::filesystem::remove(correct_path);

        if constexpr (with_logs)
        {
            auto end_program = std::chrono::high_resolution_clock::now();

            std::chrono::duration<double> total_program_time = end_program - start_program;
            std::wcout << "Program time (s): " << total_program_time.count() << std::endl
                       << "Decrypt SPEED MB/s: " << (encrypted_bytes_handl / (1024 * 1024)) / total_encrypted_time.count() << std::endl
                       << "Decrypt TIME (s): " << total_encrypted_time.count() << std::endl;
        }

        std::wcout << "File success encrypted. Close program.\n";
    }
}

template <bool with_logs>
void decrypt_directory(Kyznechik &kyz, std::wstring drop_path = L"-1")
{
    std::filesystem::path correct_path;

    if(drop_path == L"-1") {
        std::wcout << "enter DIRECTORY #: ";
        std::wstring directory;
        std::getline(std::wcin, directory);
        correct_path = std::filesystem::path(directory);
    } else {
        correct_path = drop_path;
    }

    double total_sec_time;
    std::chrono::duration<double> total_encrypted_time;
    double encrypted_bytes_handl;
    std::chrono::high_resolution_clock::time_point start_program;
    std::chrono::high_resolution_clock::time_point start;

    if constexpr (with_logs)
    {
        total_sec_time = 0;
        total_encrypted_time = std::chrono::duration<double>::zero();
        encrypted_bytes_handl = 0;
        start_program = std::chrono::high_resolution_clock::now();
    }
    std::wcout << "Start decrypt...\n";
    for (auto &path : std::filesystem::recursive_directory_iterator(correct_path))
    {
        if (path.is_regular_file() && path.path().extension() == ".enc")
        {
            if constexpr (with_logs)
            {
                start_program = std::chrono::high_resolution_clock::now();
            }

            std::ifstream this_file(path.path(), std::ios::binary);
            std::ofstream out(path.path().parent_path() /= path.path().stem(), std::ios::binary);

            assert(this_file && "Error open file...");

            std::vector<uint8_t> buffer(256 * 1024 * 1024);

            while (this_file.read(reinterpret_cast<char *>(buffer.data()), buffer.size()) || this_file.gcount() > 0)
            {
                size_t read_bytes = this_file.gcount();
                bool is_last = this_file.eof();

                if constexpr (with_logs)
                {
                    start = std::chrono::high_resolution_clock::now();
                }

                #pragma omp parallel for
                for (size_t i = 0; i < read_bytes; i += 128)
                {
                    kyz.decrypt_block(buffer.data() + i);
                }

                if (is_last)
                {
                    buffer.resize(read_bytes);
                    pkcsunpad(buffer);
                    read_bytes = buffer.size();
                }

                if constexpr (with_logs)
                {
                    std::wcout << "has been decrypted: " << path.path() << std::endl;
                }

                if constexpr (with_logs)
                {
                    auto end = std::chrono::high_resolution_clock::now();
                    total_encrypted_time += (end - start);
                    encrypted_bytes_handl += read_bytes;
                }

                out.write(reinterpret_cast<char *>(buffer.data()), read_bytes);
            }
        
            this_file.close();
            out.close();
            std::filesystem::remove(path.path());
        }
    }

    if constexpr (with_logs)
    {
        auto end_program = std::chrono::high_resolution_clock::now();

        std::chrono::duration<double> total_program_time = end_program - start_program;
        std::wcout << "Program time (s): " << total_program_time.count() << std::endl
                   << "Decrypt SPEED MB/s: " << (encrypted_bytes_handl / (1024 * 1024)) / total_encrypted_time.count() << std::endl
                   << "Decrypt TIME (s): " << total_encrypted_time.count() << std::endl;
    }
    std::wcout << "Directory success decrypted. Close program.\n";
}

#endif