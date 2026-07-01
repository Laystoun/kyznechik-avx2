#include <iostream>

#ifdef _WIN32
    #include <io.h>
    #include <fcntl.h>
#endif

#include "cli.h"


#ifdef _WIN32
int wmain(int argc, wchar_t *argv[])
#else
int main(int argc, char *argv[])
#endif
{
    setlocale(LC_ALL, "");
    #ifdef _WIN32
        _setmode(_fileno(stdin), _O_U16TEXT);
        _setmode(_fileno(stdout), _O_U16TEXT);
    #endif

    run_cli(argc, argv);

    return 0;
}