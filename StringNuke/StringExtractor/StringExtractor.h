#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <set>

struct StringInfo {
    DWORD Address;
    DWORD FileOffset;
    DWORD Length;
    std::string Content;
};

class StringExtractor {
public:

    std::vector<StringInfo> ExtractFromSection(BYTE* FileBuffer, IMAGE_SECTION_HEADER* Section, const std::set<DWORD>& ExcludeOffsets);

private:
    bool IsValidString(const char* Data, size_t MaxLength);
    bool OverlapsExclusion(DWORD Offset, DWORD Length, const std::set<DWORD>& ExcludeOffsets);
};