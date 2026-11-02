#include <windows.h>

#include <cstdio>
#include <cwchar>

int
wmain(
    _In_ int argc,
    _In_ wchar_t** argv)
{
    (void)argc;
    (void)argv;

    std::wprintf(L"test_target pid=%lu\n", GetCurrentProcessId());
    std::wprintf(L"This process stays alive until Enter is pressed.\n");
    std::wprintf(L"Press Enter to exit.\n");
    std::fflush(stdout);

    (void)std::getwchar();
    return 0;
}
