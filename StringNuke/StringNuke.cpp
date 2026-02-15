#define NOMINMAX
#include <iostream>
#include <iomanip>
#include <algorithm>
#include "PEParser/PEParser.h"
#include "StringExtractor/StringExtractor.h"
#include "Encryption/Encryption.h"
#include "DecryptionStub/DecryptionStub.h"

int main(int argc, char* argv[])
{
    std::string InputFile = argv[1];
    std::string OutputFile = InputFile.substr(0, InputFile.find_last_of('.')) + "_stripped.exe";
    BYTE XORKey = 0xAA;
    bool Verbose = true;

    std::unique_ptr<PEParser> Parser = std::make_unique<PEParser>(InputFile);
    if (!Parser->Load())
    {
        printf("Failed to load file. \n");
        return -1;
    }

    printf("- File: %s Size: %d \n", InputFile.c_str(), Parser->GetFileSize());

    std::set<DWORD> ImportOffsets = Parser->GetImportStringOffsets();
    IMAGE_SECTION_HEADER* RDataSection = Parser->GetSectionHeader(".rdata");
    if (RDataSection == nullptr)
    {
        printf("- RData Not Found. \n");
        return -2;
    }

    std::unique_ptr<StringExtractor> Extract = std::make_unique<StringExtractor>();
    std::vector<StringInfo> Strings = Extract->ExtractFromSection(Parser->GetFileBuffer(), RDataSection, ImportOffsets);
    printf("- %d strings found. \n", static_cast<std::uint32_t>(Strings.size()));

    printf("- Encrypting strings with XOR key 0x%02X...\n", XORKey);
    std::unique_ptr<Encryptor> Encrypt = std::make_unique<Encryptor>(XORKey);
    Encrypt->EncryptStrings(Parser->GetFileBuffer(), Strings, EncryptionMode::SIMPLE_XOR);
    printf("- Encrypted %d bytes\n", Encrypt->GetTotalBytesEncrypted());

    RDataSection->Characteristics |= IMAGE_SCN_MEM_WRITE;
    printf("- Made .rdata section writable\n");

    DWORD ActualEntryPoint = Parser->GetNtHeaders()->OptionalHeader.AddressOfEntryPoint;
    printf("- Original Entry Point: 0x%X\n", ActualEntryPoint);

    StubData StubCreationData;
    StubCreationData.RealEntryPoint = ActualEntryPoint;
    StubCreationData.StringCount = Strings.size();
    StubCreationData.XORKey = XORKey;

    for (const auto& String : Strings)
    {
        StubCreationData.StringAddress.push_back(String.Address);
        StubCreationData.StringLengths.push_back(String.Length);
    }

    std::unique_ptr<StubGenerator> Generator = std::make_unique<StubGenerator>();
    std::vector<BYTE> Stub = Generator->GenerateStub(StubCreationData, StubType::SIMPLE_XOR);

    printf("- Adding .decrypt section...\n");
    DWORD StubAddress = Parser->AddSection(".decrypt", (DWORD)Stub.size(), IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);

    Parser->WriteBytesToRVA(StubAddress, Stub.data(), (DWORD)Stub.size());
    printf("- Stub written at RVA: 0x%X\n", StubAddress);

    printf("- Redirecting entry point...\n");
    printf("- Old EP: 0x%X!\n", ActualEntryPoint);
    printf("- New EP: 0x%X!\n", StubAddress);
    Parser->GetNtHeaders()->OptionalHeader.AddressOfEntryPoint = StubAddress;

    if (!Parser->Save(OutputFile))
    {
        printf("- Failed to save new exe. \n");
        return -3;
    }

    printf("\n- SUCCESS! Saved to: %s\n", OutputFile.c_str());

    Sleep(5000);

    return 0;
}