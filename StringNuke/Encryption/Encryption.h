#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include "../StringExtractor/StringExtractor.h"

enum class EncryptionMode
{
    SIMPLE_XOR,
    REVERSE_XOR,
    CUSTOM
};

class Encryptor
{
public:
    Encryptor(BYTE Key) : XORKey(Key) {}

    void EncryptStrings(BYTE* FileBuffer, const std::vector<StringInfo>& Strings, EncryptionMode Mode = EncryptionMode::SIMPLE_XOR);

    DWORD GetTotalBytesEncrypted() const { return TotalBytes; }
    EncryptionMode GetMode() const { return CurrentMode; }

private:
    BYTE XORKey;
    DWORD TotalBytes = 0;
    EncryptionMode CurrentMode = EncryptionMode::SIMPLE_XOR;

    void EncryptSimple(BYTE* FileBuffer, const std::vector<StringInfo>& Strings);
    void EncryptCustom(BYTE* FileBuffer, const std::vector<StringInfo>& Strings);
};