#pragma once

#include <ntifs.h>

namespace Memory {

    bool ReadReadOnly(IN ULONGLONG address, IN PVOID buffer, IN SIZE_T size) {
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

        memcpy(buffer, reinterpret_cast<PVOID>(address), size);

        MmUnmapLockedPages(mappedAddress, mdl);
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return true;
    }

    bool WriteReadOnly(IN ULONGLONG address, IN PVOID buffer, IN SIZE_T size) {
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
