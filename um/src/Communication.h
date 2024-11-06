#pragma once

#include <Windows.h>
#include <cstdio>

typedef void(*NtCompareSigningLevelsFn)(PVOID buffer, SIZE_T size, ULONGLONG cookie);

namespace Communication {
    NtCompareSigningLevelsFn NtCompareSigningLevels = nullptr;

    bool Setup() {
        HMODULE ntDllModule = LoadLibrary("ntdll.dll");
        if (!ntDllModule) {
            fprintf(stderr, "Cannot open ntdll.dll\n");
            return false;
        }

        NtCompareSigningLevels = reinterpret_cast<NtCompareSigningLevelsFn>(GetProcAddress(ntDllModule, "NtCompareSigningLevels"));
        if (!NtCompareSigningLevels) {
            fprintf(stderr, "Cannot find NtCompareSigningLevels\n");
            return false;
        }

        return true;
    }

    void Send(PVOID buffer, SIZE_T size) {
        NtCompareSigningLevels(buffer, size, 0xABCCC2F);
    }
}