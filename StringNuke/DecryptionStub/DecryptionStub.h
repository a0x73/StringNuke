#pragma once
#include <windows.h>
#include <vector>
#include "../StringExtractor/StringExtractor.h"
#include "../Encryption/Encryption.h"

enum class StubType
{
    SIMPLE_XOR,
    CUSTOM
};

struct StubData
{
    DWORD RealEntryPoint;
    DWORD StringCount;
    BYTE XORKey;
    std::vector<DWORD> StringAddress;
    std::vector<DWORD> StringLengths;
};

class StubGenerator
{
public:
    StubGenerator() = default;
    ~StubGenerator() = default;

    std::vector<BYTE> GenerateStub(const StubData& Data, StubType Type = StubType::SIMPLE_XOR);

private:
    std::vector<BYTE> GenerateSimpleXOR(const StubData& Data);
    std::vector<BYTE> GenerateIncrementalXOR(const StubData& Data);
    std::vector<BYTE> GenerateReverseXOR(const StubData& Data);
    std::vector<BYTE> GenerateCustom(const StubData& Data);
};