// Hey! This is a modern Windows syscall implementation that gets around the usual detection methods
// Written by FURYWOLF - Feel free to use and modify this code

#pragma once
#include <ntstatus.h>
#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include <unordered_map>
#include <string>
#include <cstring>
#include <array>
#pragma comment(lib, "NTDLL")

namespace Syscalls {
    // These are our assembly functions that do the heavy lifting
    // They handle the low-level syscall operations we need
    extern "C" {
        DWORD GetSyscallId(void* funcAddress);
        void wr_eax(uint32_t id);
        void syscall_impl();
    }

    // This is our shopping list of syscalls we want to use
    // Add any new ones you need right here
    constexpr std::array<const char*, 1> syscalls{ {
        "NtAllocateVirtualMemory",  // For memory allocation 

        // Add the rest of the syscalls you wanna use 
    } };

    namespace {
        // This is where we keep track of our syscall IDs
        // Think of it as a lookup table for quick access
        struct SyscallData {
            std::unordered_map<std::string, DWORD> SyscallIds;
        } g_SyscallData;

        // Simple struct to hold PE header information
        // Makes it easier to pass around file structure info
        struct PEHeaders {
            PIMAGE_DOS_HEADER DosHeader{ nullptr };
            PIMAGE_NT_HEADERS NtHeaders{ nullptr };
            PIMAGE_SECTION_HEADER TextSection{ nullptr };
            PIMAGE_SECTION_HEADER RdataSection{ nullptr };
        };
    }

    // This function cracks open a PE file and finds all the important parts
    // Returns true if everything went well, false if something's wrong
    bool ParsePEHeaders(void* baseAddress, PEHeaders& headers) {
        if (!baseAddress) return false;

        // First, get the DOS header (every PE file starts with this)
        headers.DosHeader = static_cast<PIMAGE_DOS_HEADER>(baseAddress);
        if (headers.DosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

        // Find the modern NT headers
        headers.NtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
            static_cast<BYTE*>(baseAddress) + headers.DosHeader->e_lfanew
            );
        if (headers.NtHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

        // Look for the code (.text) and data (.rdata) sections
        auto section = IMAGE_FIRST_SECTION(headers.NtHeaders);

        for (WORD i = 0; i < headers.NtHeaders->FileHeader.NumberOfSections; i++) {
            if (std::memcmp(section[i].Name, ".text", 5) == 0) {
                headers.TextSection = &section[i];
            }
            else if (std::memcmp(section[i].Name, ".rdata", 6) == 0) {
                headers.RdataSection = &section[i];
            }
        }

        return (headers.TextSection && headers.RdataSection);
    }

    // Converts a Relative Virtual Address (RVA) to a file offset
    // Basically helps us find stuff in the PE file
    void* RvaToFileOffset(void* baseAddress, DWORD rva, const PEHeaders& headers) {
        if (!baseAddress) return nullptr;

        // Figure out which section contains our target address
        const auto section = (rva >= headers.RdataSection->VirtualAddress &&
            rva < headers.RdataSection->VirtualAddress + headers.RdataSection->Misc.VirtualSize)
            ? headers.RdataSection : headers.TextSection;

        return static_cast<BYTE*>(baseAddress) +
            (rva - section->VirtualAddress + section->PointerToRawData);
    }

    // This is where the magic happens
    // Sets up everything we need for our syscalls to work
    bool Initialize() {
        // Find and load ntdll.dll
        std::wstring systemDir(MAX_PATH, L'\0');
        auto length = GetSystemDirectoryW(systemDir.data(), MAX_PATH);
        systemDir.resize(length);
        systemDir += L"\\ntdll.dll";

        // Open the file and read it into memory
        const auto hFile = CreateFileW(systemDir.c_str(),
            GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

        if (hFile == INVALID_HANDLE_VALUE) return false;

        // Get the file size and allocate memory for it
        LARGE_INTEGER fileSize;
        if (!GetFileSizeEx(hFile, &fileSize)) {
            CloseHandle(hFile);
            return false;
        }

        // Allocate memory for our copy of ntdll
        const auto ntdllImage = VirtualAlloc(nullptr,
            static_cast<SIZE_T>(fileSize.QuadPart),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (!ntdllImage) {
            CloseHandle(hFile);
            return false;
        }

        // Read the file into our allocated memory
        DWORD bytesRead;
        const auto readSuccess = ReadFile(hFile, ntdllImage,
            static_cast<DWORD>(fileSize.QuadPart), &bytesRead, nullptr);
        CloseHandle(hFile);

        if (!readSuccess) {
            VirtualFree(ntdllImage, 0, MEM_RELEASE);
            return false;
        }

        // Parse the PE headers and find our syscalls
        PEHeaders headers;
        if (!ParsePEHeaders(ntdllImage, headers)) {
            VirtualFree(ntdllImage, 0, MEM_RELEASE);
            return false;
        }

        // Get the export directory - this is where all the function info lives
        const auto exportDir = static_cast<PIMAGE_EXPORT_DIRECTORY>(
            RvaToFileOffset(ntdllImage,
                headers.NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress,
                headers)
            );

        // Get pointers to the function info arrays
        const auto functions = static_cast<PDWORD>(
            RvaToFileOffset(ntdllImage, exportDir->AddressOfFunctions, headers)
            );
        const auto names = static_cast<PDWORD>(
            RvaToFileOffset(ntdllImage, exportDir->AddressOfNames, headers)
            );
        const auto ordinals = static_cast<PWORD>(
            RvaToFileOffset(ntdllImage, exportDir->AddressOfNameOrdinals, headers)
            );

        // Find and store all our syscall IDs
        for (const auto& syscallName : syscalls) {
            for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
                const auto currentName = static_cast<const char*>(
                    RvaToFileOffset(ntdllImage, names[i], headers)
                    );

                if (std::strcmp(currentName, syscallName) == 0) {
                    const auto ordinal = ordinals[i];
                    const auto funcAddr = RvaToFileOffset(ntdllImage, functions[ordinal], headers);
                    const auto syscallId = GetSyscallId(funcAddr);
                    g_SyscallData.SyscallIds[syscallName] = syscallId;
                    break;
                }
            }
        }

        // Clean up and return
        VirtualFree(ntdllImage, 0, MEM_RELEASE);
        return !g_SyscallData.SyscallIds.empty();
    }

    // Clean up our syscall data when we're done
    void Cleanup() {
        g_SyscallData.SyscallIds.clear();
    }

    // This is the core function that actually makes the syscalls happen
    // It's templated so it can handle any type of syscall
    template<typename T, typename... Ts>
    [[nodiscard]] __forceinline T syscall(uint32_t id, Ts&&... args) {
        wr_eax(id);  // Set up the syscall ID
        return reinterpret_cast<T(*)(Ts...)>(&syscall_impl)(std::forward<Ts>(args)...);
    }

    // This is the main function you'll use to make syscalls
    // Just give it the name and arguments, and it handles the rest
    template<typename... Args>
    [[nodiscard]] NTSTATUS Call(const char* syscallName, Args&&... args) {
        const auto it = g_SyscallData.SyscallIds.find(syscallName);
        if (it == g_SyscallData.SyscallIds.end()) {
            std::cerr << "[-] Syscall '" << syscallName << "' not found\n";
            return STATUS_PROCEDURE_NOT_FOUND;
        }

        return syscall<NTSTATUS>(it->second, std::forward<Args>(args)...);
    }
}