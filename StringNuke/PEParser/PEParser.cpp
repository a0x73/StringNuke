#define _CRT_SECURE_NO_WARNINGS

#include "PEParser.h"
#include <fstream>
#include <iostream>
#include <iomanip>
#include <set>

PEParser::PEParser(const std::string& FilePath) : FilePath(FilePath), FileBuffer(nullptr), FileSize(0), DOSHeader(nullptr), NTHeaders(nullptr), SectionHeaders(nullptr)
{
}

PEParser::~PEParser()
{
    delete[] FileBuffer;
}

bool PEParser::Load() 
{
    std::ifstream File(FilePath, std::ios::binary | std::ios::ate);
    if (!File.is_open())
    {
        printf("/ Failed to open file. \n");
        return false;
    }

    FileSize = (DWORD)File.tellg();
    File.seekg(0, std::ios::beg);

    FileBuffer = new BYTE[FileSize];
    File.read((char*)FileBuffer, FileSize);
    File.close();

    // Parse PE headers
    DOSHeader = (IMAGE_DOS_HEADER*)FileBuffer;
    if (DOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("/ Invalid DOS signature \n");
        return false;
    }

    NTHeaders = (IMAGE_NT_HEADERS*)(FileBuffer + DOSHeader->e_lfanew);
    if (NTHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("/ Invalid PE signature \n");
        return false;
    }

    SectionHeaders = IMAGE_FIRST_SECTION(NTHeaders);

    return true;
}

bool PEParser::Save(const std::string& OutputPath)
{
    std::ofstream File(OutputPath, std::ios::binary);
    if (!File.is_open())
    {
        printf("/ Failed to create: %s \n", OutputPath.c_str());
        return false;
    }

    File.write((char*)FileBuffer, FileSize);
    File.close();
    return true;
}

IMAGE_SECTION_HEADER* PEParser::GetSectionHeader(const char* name)
{
    for (WORD i = 0; i < NTHeaders->FileHeader.NumberOfSections; i++)
    {
        if (memcmp(SectionHeaders[i].Name, name, strlen(name)) == 0)
        {
            return &SectionHeaders[i];
        }
    }
    return nullptr;
}

DWORD PEParser::RVAToFileOffset(DWORD Address)
{
    for (WORD i = 0; i < NTHeaders->FileHeader.NumberOfSections; i++)
    {
        DWORD SectionStart = SectionHeaders[i].VirtualAddress;
        DWORD SectionEnd = SectionStart + SectionHeaders[i].Misc.VirtualSize;

        if (Address >= SectionStart && Address < SectionEnd)
        {
            DWORD Offset = Address - SectionStart;
            return SectionHeaders[i].PointerToRawData + Offset;
        }
    }
    return 0;
}

std::set<DWORD> PEParser::GetImportStringOffsets()
{
    std::set<DWORD> ImportOffsets;

    // Get import directory
    IMAGE_DATA_DIRECTORY* ImportDirectory = &NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (ImportDirectory->VirtualAddress == 0 || ImportDirectory->Size == 0)
    {
        return ImportOffsets; // No imports
    }

    DWORD ImportDirectoryOffset = RVAToFileOffset(ImportDirectory->VirtualAddress);
    IMAGE_IMPORT_DESCRIPTOR* ImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)(FileBuffer + ImportDirectoryOffset);

    // Iterate through each imported DLL
    while (ImportDescriptor->Name != 0)
    {
        // Get DLL name location
        DWORD DLLNameOffset = RVAToFileOffset(ImportDescriptor->Name);
        if (DLLNameOffset > 0)
        {
            const char* DLLName = (const char*)(FileBuffer + DLLNameOffset);
            DWORD DLLNameLength = (DWORD)strlen(DLLName) + 1; // Include null terminator

            printf("-- DLL: %s at offset 0x%lx \n", DLLName, DLLNameOffset);
            // Add all bytes of this string to exclusion set
            for (DWORD i = 0; i < DLLNameLength; i++)
            {
                ImportOffsets.insert(DLLNameOffset + i);
            }
        }

        // Get function names (Original First Thunk or First Thunk)
        DWORD ThunkAddress = ImportDescriptor->OriginalFirstThunk;
        if (ThunkAddress == 0)
        {
            ThunkAddress = ImportDescriptor->FirstThunk;
        }

        if (ThunkAddress != 0)
        {
            DWORD ThunkOffset = RVAToFileOffset(ThunkAddress);
            IMAGE_THUNK_DATA64* Thunk = (IMAGE_THUNK_DATA64*)(FileBuffer + ThunkOffset);

            while (Thunk->u1.AddressOfData != 0)
            {
                if (!(Thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64))
                {
                    DWORD NameAddress = (DWORD)Thunk->u1.AddressOfData;
                    DWORD NameOffset = RVAToFileOffset(NameAddress);

                    if (NameOffset > 0)
                    {
                        NameOffset += 2;

                        const char* FunctionName = (const char*)(FileBuffer + NameOffset);
                        DWORD FunctionNameLength = (DWORD)strlen(FunctionName) + 1;

                        for (DWORD i = 0; i < FunctionNameLength; i++)
                        {
                            ImportOffsets.insert(NameOffset + i);
                        }
                    }
                }
                Thunk++;
            }
        }

        ImportDescriptor++;
    }

    printf(" - %llu bytes in import (strings excluded)", ImportOffsets.size());

    return ImportOffsets;
}

void PEParser::PrintImportInfo()
{
    IMAGE_DATA_DIRECTORY* ImportDirectory = &NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    std::cout << "\n- Import Directory:" << std::endl;
    std::cout << "-- Address: 0x" << std::hex << ImportDirectory->VirtualAddress << std::dec << std::endl;
    std::cout << "-- Size: " << ImportDirectory->Size << " bytes" << std::endl;
}

DWORD PEParser::AlignUp(DWORD Value, DWORD Alignment)
{
    return (Value + Alignment - 1) & ~(Alignment - 1);
}

DWORD PEParser::AddSection(const char* Name, DWORD Size, DWORD Characteristics)
{
    // Find last section
    IMAGE_SECTION_HEADER* LastSection = &SectionHeaders[NTHeaders->FileHeader.NumberOfSections - 1];
    IMAGE_SECTION_HEADER* NewSection = LastSection + 1;

    memset(NewSection, 0, sizeof(IMAGE_SECTION_HEADER));
    strncpy((char*)NewSection->Name, Name, 8);

    DWORD LastVirtualEnd = LastSection->VirtualAddress + LastSection->Misc.VirtualSize;
    NewSection->VirtualAddress = AlignUp(LastVirtualEnd, NTHeaders->OptionalHeader.SectionAlignment);
    NewSection->Misc.VirtualSize = Size;
    DWORD LastRawEnd = LastSection->PointerToRawData + LastSection->SizeOfRawData;
    NewSection->PointerToRawData = AlignUp(LastRawEnd, NTHeaders->OptionalHeader.FileAlignment);
    NewSection->SizeOfRawData = AlignUp(Size, NTHeaders->OptionalHeader.FileAlignment);
    NewSection->Characteristics = Characteristics;

    NTHeaders->FileHeader.NumberOfSections++;
    NTHeaders->OptionalHeader.SizeOfImage = NewSection->VirtualAddress + AlignUp(NewSection->Misc.VirtualSize, NTHeaders->OptionalHeader.SectionAlignment);

    DWORD NewFileSize = NewSection->PointerToRawData + NewSection->SizeOfRawData;
    if (NewFileSize > FileSize)
    {
        BYTE* NewBuffer = new BYTE[NewFileSize];
        memset(NewBuffer, 0, NewFileSize);
        memcpy(NewBuffer, FileBuffer, FileSize);

        // Update pointers
        DWORD DOSHeaderOffset = (BYTE*)DOSHeader - FileBuffer;
        DWORD NTHeadersOffset = (BYTE*)NTHeaders - FileBuffer;
        DWORD SectionOffset = (BYTE*)SectionHeaders - FileBuffer;

        delete[] FileBuffer;
        FileBuffer = NewBuffer;
        FileSize = NewFileSize;

        DOSHeader = (IMAGE_DOS_HEADER*)(FileBuffer + DOSHeaderOffset);
        NTHeaders = (IMAGE_NT_HEADERS*)(FileBuffer + NTHeadersOffset);
        SectionHeaders = (IMAGE_SECTION_HEADER*)(FileBuffer + SectionOffset);
    }

    printf("- Added section %s at 0xllx", Name, NewSection->VirtualAddress);

    return NewSection->VirtualAddress;
}

void PEParser::WriteBytesToRVA(DWORD Address, const BYTE* Data, DWORD Size)
{
    DWORD FileOffset = RVAToFileOffset(Address);
    if (FileOffset > 0 && FileOffset + Size <= FileSize)
    {
        memcpy(FileBuffer + FileOffset, Data, Size);
    }
}