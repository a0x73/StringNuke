#include "Encryption.h"
#include <algorithm>
#include <iostream>

void Encryptor::EncryptStrings(BYTE* FileBuffer, const std::vector<StringInfo>& Strings,EncryptionMode Mode)
{
    TotalBytes = 0;
    CurrentMode = Mode;

    const char* ModeName[] = { "SIMPLE_XOR", "CUSTOM" };
    printf("- Using encryption mode: %s\n", ModeName[(int)Mode]);

    switch (Mode) {
    case EncryptionMode::SIMPLE_XOR:
        EncryptSimple(FileBuffer, Strings);
        break;

    case EncryptionMode::CUSTOM:
        EncryptCustom(FileBuffer, Strings);
        break;
    }
}

void Encryptor::EncryptSimple(BYTE* FileBuffer, const std::vector<StringInfo>& Strings)
{
    for (const auto& String : Strings)
    {
        BYTE* Location = FileBuffer + String.FileOffset;

        for (DWORD i = 0; i < String.Length; i++)
        {
            Location[i] ^= XORKey;
        }

        TotalBytes += String.Length;
    }
}


void Encryptor::EncryptCustom(BYTE* FileBuffer, const std::vector<StringInfo>& Strings)
{
    printf("/ CUSTOM mode not implemented yet!\n");
    printf("/ Falling back to SIMPLE_XOR\n");
    EncryptSimple(FileBuffer, Strings);
}