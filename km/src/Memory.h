#pragma once

#include <ntddk.h>

namespace Memory {

    bool WriteToReadOnly(ULONGLONG address, PVOID buffer, SIZE_T size) {
        PMDL mdl = IoAllocateMdl(reinterpret_cast<PVOID>(address), size, FALSE, FALSE, nullptr);
        if (!mdl)
            return false;

        __try {
                MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }

        PVOID mappedAddress = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, nullptr, FALSE, NormalPagePriority);
        if (!mappedAddress)
            return false;

        MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);

        memcpy(mappedAddress, buffer, size);

        MmUnmapLockedPages(mappedAddress, mdl);
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return true;
    }
}
