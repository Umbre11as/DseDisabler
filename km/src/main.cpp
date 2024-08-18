#include "Memory.h"
#include <ntstrsafe.h>

#define Log(format, ...) DbgPrintEx(0, 0, format, __VA_ARGS__)

enum _LDR_HOT_PATCH_STATE {
    LdrHotPatchBaseImage = 0,
    LdrHotPatchNotApplied = 1,
    LdrHotPatchAppliedReverse = 2,
    LdrHotPatchAppliedForward = 3,
    LdrHotPatchFailedToPatch = 4,
    LdrHotPatchStateMax = 5
};

enum _LDR_DLL_LOAD_REASON {
    LoadReasonStaticDependency = 0,
    LoadReasonStaticForwarderDependency = 1,
    LoadReasonDynamicForwarderDependency = 2,
    LoadReasonDelayloadDependency = 3,
    LoadReasonDynamicLoad = 4,
    LoadReasonAsImageLoad = 5,
    LoadReasonAsDataLoad = 6,
    LoadReasonEnclavePrimary = 7,
    LoadReasonEnclaveDependency = 8,
    LoadReasonPatchImage = 9,
    LoadReasonUnknown = -1
};

typedef struct _LDR_DATA_TABLE_ENTRY {
    struct _LIST_ENTRY InLoadOrderLinks; //0x0
    struct _LIST_ENTRY InMemoryOrderLinks; //0x10
    struct _LIST_ENTRY InInitializationOrderLinks; //0x20
    VOID* DllBase; //0x30
    VOID* EntryPoint; //0x38
    ULONG SizeOfImage; //0x40
    struct _UNICODE_STRING FullDllName; //0x48
    struct _UNICODE_STRING BaseDllName; //0x58
    union {
        UCHAR FlagGroup[4]; //0x68
        ULONG Flags; //0x68
        struct {
            ULONG PackagedBinary:1; //0x68
            ULONG MarkedForRemoval:1; //0x68
            ULONG ImageDll:1; //0x68
            ULONG LoadNotificationsSent:1; //0x68
            ULONG TelemetryEntryProcessed:1; //0x68
            ULONG ProcessStaticImport:1; //0x68
            ULONG InLegacyLists:1; //0x68
            ULONG InIndexes:1; //0x68
            ULONG ShimDll:1; //0x68
            ULONG InExceptionTable:1; //0x68
            ULONG ReservedFlags1:2; //0x68
            ULONG LoadInProgress:1; //0x68
            ULONG LoadConfigProcessed:1; //0x68
            ULONG EntryProcessed:1; //0x68
            ULONG ProtectDelayLoad:1; //0x68
            ULONG ReservedFlags3:2; //0x68
            ULONG DontCallForThreads:1; //0x68
            ULONG ProcessAttachCalled:1; //0x68
            ULONG ProcessAttachFailed:1; //0x68
            ULONG CorDeferredValidate:1; //0x68
            ULONG CorImage:1; //0x68
            ULONG DontRelocate:1; //0x68
            ULONG CorILOnly:1; //0x68
            ULONG ChpeImage:1; //0x68
            ULONG ChpeEmulatorImage:1; //0x68
            ULONG ReservedFlags5:1; //0x68
            ULONG Redirected:1; //0x68
            ULONG ReservedFlags6:2; //0x68
            ULONG CompatDatabaseProcessed:1; //0x68
        };
    };
    USHORT ObsoleteLoadCount; //0x6c
    USHORT TlsIndex; //0x6e
    struct _LIST_ENTRY HashLinks; //0x70
    ULONG TimeDateStamp; //0x80
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext; //0x88
    VOID* Lock; //0x90
    struct _LDR_DDAG_NODE* DdagNode; //0x98
    struct _LIST_ENTRY NodeModuleLink; //0xa0
    struct _LDRP_LOAD_CONTEXT* LoadContext; //0xb0
    VOID* ParentDllBase; //0xb8
    VOID* SwitchBackContext; //0xc0
    struct _RTL_BALANCED_NODE BaseAddressIndexNode; //0xc8
    struct _RTL_BALANCED_NODE MappingInfoIndexNode; //0xe0
    ULONGLONG OriginalBase; //0xf8
    union _LARGE_INTEGER LoadTime; //0x100
    ULONG BaseNameHashValue; //0x108
    enum _LDR_DLL_LOAD_REASON LoadReason; //0x10c
    ULONG ImplicitPathOptions; //0x110
    ULONG ReferenceCount; //0x114
    ULONG DependentLoadFlags; //0x118
    UCHAR SigningLevel; //0x11c
    ULONG CheckSum; //0x120
    VOID* ActivePatchImageBase; //0x128
    enum _LDR_HOT_PATCH_STATE HotPatchState; //0x130
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length; //0x0
    UCHAR Initialized; //0x4
    VOID* SsHandle; //0x8
    struct _LIST_ENTRY InLoadOrderModuleList; //0x10
    struct _LIST_ENTRY InMemoryOrderModuleList; //0x20
    struct _LIST_ENTRY InInitializationOrderModuleList; //0x30
    VOID* EntryInProgress; //0x40
    UCHAR ShutdownInProgress; //0x48
    VOID* ShutdownThreadId; //0x50
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
private:
    unsigned char _pad0[0x18];
public:
    PPEB_LDR_DATA Ldr; //0x18
} PEB, *PPEB;

typedef struct _EPROCESS {
private:
    unsigned char _pad0[0x550];
public:
    PPEB Peb; //0x550
} EPROCESS, *PEPROCESS;

typedef NTSTATUS(*DRIVER_ENTRYPOINT)(PDRIVER_OBJECT, PUNICODE_STRING);
extern "C" {
    NTKERNELAPI PVOID NTAPI RtlFindExportedRoutineByName(
            IN PVOID ImageBase,
            IN PCCH RoutineNam
    );

    NTKERNELAPI NTSTATUS NTAPI IoCreateDriver(
            IN PUNICODE_STRING Name,
            IN DRIVER_ENTRYPOINT DriverInit
    );
}

UNICODE_STRING DRIVER_NAME = RTL_CONSTANT_STRING(L"\\Driver\\Fuckyoublume");
UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\Fuckyoublume");
UNICODE_STRING DEVICE_LINK = RTL_CONSTANT_STRING(L"\\DosDevices\\Fuckyoublume");

NTSTATUS DriverInitialize(PDRIVER_OBJECT, PUNICODE_STRING) {
    UNICODE_STRING functionName;
    RtlInitUnicodeString(&functionName, L"PsLoadedModuleList");
    auto moduleList = reinterpret_cast<PLIST_ENTRY>(MmGetSystemRoutineAddress(&functionName));
    if (!moduleList)
        return STATUS_NOT_FOUND;

    PVOID ciBase = nullptr;
    for (PLIST_ENTRY link = moduleList; link != moduleList->Blink; link = link->Flink) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (entry && wcscmp(entry->BaseDllName.Buffer, L"CI.dll") == 0) {
            ciBase = entry->DllBase;
            break;
        }
    }
    if (!ciBase)
        return STATUS_NOT_FOUND;

    PVOID ciInitialize = RtlFindExportedRoutineByName(ciBase, "CiInitialize");
    int newValue = 6;
    Memory::WriteToReadOnly(reinterpret_cast<ULONGLONG>(ciInitialize) + 0xB008, &newValue, sizeof(newValue));

    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath) {
    if (driverObject)
        return DriverInitialize(driverObject, registryPath);

    // Manual mapped driver
    __try {
        Log("IoCreateDriver status: %08X\n", IoCreateDriver(&DRIVER_NAME, &DriverInitialize));
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log("IoCreateDriver failed with error code: %08X\n", GetExceptionCode());
        return STATUS_DRIVER_UNABLE_TO_LOAD;
    }

    return STATUS_SUCCESS;
}
