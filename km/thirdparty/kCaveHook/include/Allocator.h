#pragma once

#include <ntifs.h>

namespace Allocator {

    PVOID AllocateKernel(IN SIZE_T size, IN ULONG tag = 0) {
        return ExAllocatePoolWithTag(NonPagedPool, size, tag);
    }

    void FreeKernel(IN PVOID buffer, IN ULONG tag = 0) {
        if (tag == 0)
            ExFreePool(buffer);
        else
            ExFreePoolWithTag(buffer, tag);
    }
}
