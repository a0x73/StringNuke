#include "StringExtractor.h"
#include <cctype>

bool StringExtractor::IsValidString(const char* Data, size_t MaxLength) {
    if (!Data || MaxLength < 4) return false;

    size_t Length = 0;
    int PrintableCount = 0;

    while (Length < MaxLength && Data[Length] != '\0')
    {
        unsigned char c = (unsigned char)Data[Length];

        if ((c >= 32 && c <= 126) || c == '\n' || c == '\r' || c == '\t')
        {
            PrintableCount++;
        }
        else
        {
            return false;
        }

        Length++;
        if (Length > 1024)
        {
            return false;
        }
    }
    if (Length < 4 || Length > 1024 || Data[Length] != '\0')
    {
        return false;
    }

    return (float)PrintableCount / Length >= 0.8f;
}

bool StringExtractor::OverlapsExclusion(DWORD Offset, DWORD Length, const std::set<DWORD>& ExcludeOffsets)
{
    // Check if any byte of this string is in the exclusion set
    for (DWORD i = 0; i < Length; i++)
    {
        if (ExcludeOffsets.find(Offset + i) != ExcludeOffsets.end())
        {
            return true;
        }
    }
    return false;
}

std::vector<StringInfo> StringExtractor::ExtractFromSection(BYTE* FileBuffer,IMAGE_SECTION_HEADER* Section, const std::set<DWORD>& ExcludeOffsets)
{
    std::vector<StringInfo> Strings;

    DWORD SectionStart = Section->PointerToRawData;
    DWORD SectionSize = Section->SizeOfRawData;
    DWORD SectionAddress = Section->VirtualAddress;

    for (DWORD i = 0; i < SectionSize; i++)
    {
        const char* PotentialString = (const char*)(FileBuffer + SectionStart + i);

        if (IsValidString(PotentialString, SectionSize - i))
        {
            size_t Length = strlen(PotentialString);
            DWORD FileOffset = SectionStart + i;

            // Skip if this string overlaps with import strings
            if (!OverlapsExclusion(FileOffset, (DWORD)Length, ExcludeOffsets))
            {
                StringInfo Info;
                Info.Address = SectionAddress + i;
                Info.FileOffset = FileOffset;
                Info.Length = (DWORD)Length;
                Info.Content = std::string(PotentialString, Length);

                Strings.push_back(Info);
            }

            i += Length;
        }
    }

    return Strings;
}