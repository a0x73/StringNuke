#pragma once
#include <windows.h>
#include <string>
#include <set>

class PEParser
{
public:
    PEParser(const std::string& FilePath);
    ~PEParser();

    bool Load();
    bool Save(const std::string& OutputPath);

    // Getters
    IMAGE_SECTION_HEADER* GetSectionHeader(const char* Name);
    IMAGE_NT_HEADERS* GetNtHeaders() { return NTHeaders; }
    IMAGE_DOS_HEADER* GetDosHeader() { return DOSHeader; }
    BYTE* GetFileBuffer() { return FileBuffer; }
    DWORD GetFileSize() { return FileSize; }
    bool Is64Bit() { return NTHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC; }

    // Import parsing
    std::set<DWORD> GetImportStringOffsets();

    // Section manipulation
    DWORD AddSection(const char* Name, DWORD Size, DWORD Characteristics);
    void WriteBytesToRVA(DWORD Address, const BYTE* Data, DWORD Size);
    DWORD RVAToFileOffset(DWORD Address);

    // Info
    void PrintImportInfo();

private:
    std::string FilePath;
    BYTE* FileBuffer;
    DWORD FileSize;

    IMAGE_DOS_HEADER* DOSHeader;
    IMAGE_NT_HEADERS* NTHeaders;
    IMAGE_SECTION_HEADER* SectionHeaders;

    DWORD AlignUp(DWORD Value, DWORD Alignment);
};