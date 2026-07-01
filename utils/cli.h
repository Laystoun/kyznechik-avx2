#ifndef CLI_H
#define CLI_H

#include "kyznechik.h"

int run_cli(int argc, wchar_t** argv); // или char** на Linux, через #ifdef
int handle_drop(Kyznechik& kyz, wchar_t* dropped_path);
int handle_menu(Kyznechik& kyz);

#endif