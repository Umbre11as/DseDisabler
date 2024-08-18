#include <Windows.h>
#include <cstdio>
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

int main() {
    // Credits https://github.com/CaledoniaProject/FindCiOptions, I found the DONT_RESOLVE_DLL_REFERENCES flag there
    const HMODULE ciModule = LoadLibraryEx(R"(C:\Windows\System32\ci.dll)", nullptr, DONT_RESOLVE_DLL_REFERENCES);
    const auto ciInitialize = reinterpret_cast<ULONGLONG>(GetProcAddress(ciModule, "CiInitialize"));
    const ULONGLONG cipInitialize = FindCipInitialize(ciInitialize);
    const ULONGLONG g_CiOptionsAddress = Findg_CiOptions(cipInitialize);
    const ULONGLONG offset = ciInitialize - g_CiOptionsAddress;
    printf("Offset from CiInitialize: %llX\n", offset);

    return 0;
}
