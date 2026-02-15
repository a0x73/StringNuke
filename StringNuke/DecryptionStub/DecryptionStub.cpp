#include "DecryptionStub.h"
#include <iostream>

std::vector<BYTE> StubGenerator::GenerateStub(const StubData& Data, StubType Type)
{
    const char* TypeNames[] = { "SIMPLE_XOR", "CUSTOM" };
    printf("- Generating %s decryption stub\n", TypeNames[(int)Type]);

    switch (Type)
    {
    case StubType::SIMPLE_XOR:
        return GenerateSimpleXOR(Data);
    case StubType::CUSTOM:
        return GenerateCustom(Data);
    default:
        printf("/ Unknown stub type!\n");
        return std::vector<BYTE>();
    }
}

std::vector<BYTE> StubGenerator::GenerateSimpleXOR(const StubData& Data)
{
    std::vector<BYTE> Stub;

    // Save registers
    Stub.push_back(0x50); // push rax
    Stub.push_back(0x51); // push rcx
    Stub.push_back(0x52); // push rdx

    // Get ImageBase from PEB
    Stub.insert(Stub.end(),
    {
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00  // mov rax, gs:[60h]
    });
    Stub.insert(Stub.end(),
    {
        0x48, 0x8B, 0x40, 0x10  // mov rax, [rax+10h]
    });

    // Decrypt each string
    for (size_t i = 0; i < Data.StringCount; i++)
    {
        DWORD Address = Data.StringAddress[i];
        DWORD Length = Data.StringLengths[i];

        // lea rdx, [rax + RVA]  ; rdx = string address
        Stub.insert(Stub.end(), { 0x48, 0x8D, 0x90 });
        Stub.push_back((Address >> 0) & 0xFF);
        Stub.push_back((Address >> 8) & 0xFF);
        Stub.push_back((Address >> 16) & 0xFF);
        Stub.push_back((Address >> 24) & 0xFF);

        // mov ecx, length
        Stub.push_back(0xB9);
        Stub.push_back((Length >> 0) & 0xFF);
        Stub.push_back((Length >> 8) & 0xFF);
        Stub.push_back((Length >> 16) & 0xFF);
        Stub.push_back((Length >> 24) & 0xFF);

        // decrypt_loop:
        // xor byte ptr [rdx], key
        Stub.insert(Stub.end(), { 0x80, 0x32 });
        Stub.push_back(Data.XORKey);

        // inc rdx
        Stub.insert(Stub.end(), { 0x48, 0xFF, 0xC2 });

        // loop (dec ecx, jnz)
        Stub.push_back(0xE2);
        Stub.push_back(0xF8); // -8 bytes
    }

    // Restore registers
    Stub.push_back(0x5A); // pop rdx
    Stub.push_back(0x59); // pop rcx
    Stub.push_back(0x58); // pop rax

    // Get ImageBase again and jump to OEP
    Stub.insert(Stub.end(),
    {
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00  // mov rax, gs:[60h]
    });
    Stub.insert(Stub.end(),
    {
        0x48, 0x8B, 0x40, 0x10  // mov rax, [rax+10h]
    });

    // add rax, RealEntryPoint  ; RAX = ImageBase + RealEntryPoint
    Stub.insert(Stub.end(), { 0x48, 0x05 });
    Stub.push_back((Data.RealEntryPoint >> 0) & 0xFF);
    Stub.push_back((Data.RealEntryPoint >> 8) & 0xFF);
    Stub.push_back((Data.RealEntryPoint >> 16) & 0xFF);
    Stub.push_back((Data.RealEntryPoint >> 24) & 0xFF);

    // jmp rax
    Stub.insert(Stub.end(), { 0xFF, 0xE0 });

    printf("- Stub size: %d bytes\n", (int)Stub.size());
    return Stub;
}

std::vector<BYTE> StubGenerator::GenerateCustom(const StubData& Data)
{
    printf("/ CUSTOM stub not implemented - returning empty stub\n");
    return std::vector<BYTE>();
}