#pragma once

#include <ntifs.h>
#include "Errors.h"

struct ByteBuffer {
    UCHAR* buffer;
    SIZE_T size;
};

typedef struct HOOK_DATA_ {
    ULONGLONG Target;
    PVOID Detour;
    PVOID Trampoline;
    ByteBuffer Prologue;
} HOOK_DATA, *PHOOK_DATA, *LPHOOK_DATA;

bool CaveHookEx(IN ULONGLONG target, IN PVOID detour, OUT PVOID* original, OUT HOOK_DATA* hookData);
bool CaveHook(IN ULONGLONG target, IN PVOID detour, OUT PVOID* original);
int CaveLastError();
