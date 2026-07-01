#include "benchmark.h"

#include <vector>

void speed_test(Kyznechik& kyz) {
    for (int i = 0; i < 32; i++) kyz.master_key[i] = i ^ 0x00;

    const size_t BUFF_SIZE = 1024 * 1024 * 1024;
    std::vector<uint8_t> buff(BUFF_SIZE);

    for (int x = 0; x < BUFF_SIZE; x++) buff[x] = uint8_t(x ^ 0xC3);

    std::wcout << "Start In-Memory benchmark" << std::endl;

    auto start = std::chrono::high_resolution_clock::now();

    #pragma omp parallel for    
    for(int off = 0; off < BUFF_SIZE; off += 128) {
        kyz.encrypt_block(buff.data() + off);
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = end - start;

    // 3. Считаем скорость
    double gigabytes = (double)BUFF_SIZE / (1024 * 1024 * 1024);
    double speed = gigabytes / diff.count();

    std::wcout << "Time: " << diff.count() << " seconds" << std::endl;
    std::wcout << "Pure Speed: " << speed << " GB/s" << std::endl << std::endl;

    return;
}