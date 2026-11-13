#pragma once

#if !defined(_NTDDK_) && !defined(_NTIFS_)
#include <ntddk.h>
#endif

//
// All driver diagnostics go to the kernel debugger / DebugView. The driver
// never writes to files or the registry.
//
#define PPL_LOG(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, \
               "[MakeMePPL] " fmt "\n", ##__VA_ARGS__)
