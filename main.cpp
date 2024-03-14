#ifdef _WIN64
#define PEB_OFFSET 0x60
#else
#define PEB_OFFSET 0x30
#endif

#include "windows.h"
#include "winternl.h"
#include <iostream>
#include <string>

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);

typedef NTSTATUS (NTAPI *pNtFreeVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType);

typedef NTSTATUS (NTAPI *pLdrLoadDll)(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle);

typedef BOOL (WINAPI *pCreateProcessW)(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);

void* GetFunctionAddress(PVOID baseAddress, const char* functionName) {
    auto dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
    auto ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)baseAddress + dosHeader->e_lfanew);

    auto exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)baseAddress + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    auto functions = (PDWORD)((PBYTE)baseAddress + exportDirectory->AddressOfFunctions);
    auto names = (PDWORD)((PBYTE)baseAddress + exportDirectory->AddressOfNames);
    auto ordinals = (PWORD)((PBYTE)baseAddress + exportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
        const char* exportName = (const char*)baseAddress + names[i];
        if (_stricmp(exportName, functionName) == 0) {
            DWORD functionRVA = functions[ordinals[i]];
            return (PBYTE)baseAddress + functionRVA;
        }
    }

    return nullptr;
}

std::wstring ReadUnicodeString(const UNICODE_STRING& unicodeString) {
    return std::wstring(unicodeString.Buffer, unicodeString.Length / sizeof(WCHAR));
}

void InitializeUnicodeString(UNICODE_STRING* DestinationString, PCWSTR SourceString) {
    DestinationString->Buffer = const_cast<PWSTR>(SourceString);
    DestinationString->Length = wcslen(SourceString) * sizeof(WCHAR);
    DestinationString->MaximumLength = DestinationString->Length + sizeof(WCHAR);
}

void FindNtdll() {
    // Access the PEB directly from the TEB (Thread Environment Block)
    PEB* peb = reinterpret_cast<PEB*>(__readgsqword(PEB_OFFSET)); // For x64
    // For x86, use: PEB* peb = reinterpret_cast<PEB*>(__readfsdword(PEB_OFFSET));

    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY* moduleList = &ldr->InMemoryOrderModuleList;

    for (LIST_ENTRY* entry = moduleList->Flink; entry != moduleList; entry = entry->Flink) {
        LDR_DATA_TABLE_ENTRY* moduleEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        std::wstring dllName = ReadUnicodeString(moduleEntry->FullDllName);

        std::wcout << L"found:" << dllName << std::endl;

        if (dllName.find(L"ntdll.dll") != std::wstring::npos) {
            std::wcout << L"Found ntdll.dll: " << dllName << std::endl;
            std::wcout << L"Base Address: " << moduleEntry->DllBase << std::endl;

            auto NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetFunctionAddress(moduleEntry->DllBase, "NtAllocateVirtualMemory");
            auto NtFreeVirtualMemory = (pNtFreeVirtualMemory)GetFunctionAddress(moduleEntry->DllBase, "NtFreeVirtualMemory");
            
            auto LdrLoadDllFunc = (pLdrLoadDll)GetFunctionAddress(moduleEntry->DllBase, "LdrLoadDll");
            if (!LdrLoadDllFunc) {
                std::cerr << "Failed to get address of LdrLoadDll." << std::endl;
                return;
            }

            UNICODE_STRING dllName;
            InitializeUnicodeString(&dllName, L"kernel32.dll");

            HANDLE moduleHandle = nullptr;
            // Attempt to load kernel32.dll
            NTSTATUS status = LdrLoadDllFunc(nullptr, 0, &dllName, &moduleHandle);

            if (NT_SUCCESS(status)) {
                std::wcout << L"kernel32.dll loaded successfully. Module handle: " << moduleHandle << std::endl;

                auto CreateProcessWFunc = (pCreateProcessW)GetFunctionAddress(moduleHandle, "CreateProcessW");
                if (CreateProcessWFunc) {
                    std::wcout << L"Address of CreateProcessW retrieved successfully." << std::endl;

                    STARTUPINFOW si = {};
                    PROCESS_INFORMATION pi = {};
                    ZeroMemory(&si, sizeof(si));
                    si.cb = sizeof(si);
                    ZeroMemory(&pi, sizeof(pi));

                    wchar_t cmdLine[] = L"cmd.exe /C dir";

                    BOOL result = CreateProcessWFunc(
                        nullptr,              // No module name (use command line)
                        cmdLine,              // Command line - needs to be mutable
                        nullptr,              // Process handle not inheritable
                        nullptr,              // Thread handle not inheritable
                        FALSE,                // Set handle inheritance to FALSE
                        0,                    // No creation flags
                        nullptr,              // Use parent's environment block
                        nullptr,              // Use parent's starting directory 
                        &si,                  // Pointer to STARTUPINFO structure
                        &pi                   // Pointer to PROCESS_INFORMATION structure
                    );

                    if (result) {
                        std::wcout << L"CreateProcessW succeeded." << std::endl;
                        CloseHandle(pi.hProcess);
                        CloseHandle(pi.hThread);
                    } else {
                        std::wcout << L"CreateProcessW failed. Error: " << GetLastError() << std::endl;
                    }
                } else {
                    std::wcerr << L"Failed to get address of CreateProcessW." << std::endl;
                }
            } else {
                std::wcout << L"Failed to load kernel32.dll. Status: " << status << std::endl;
            }

            if (!NtAllocateVirtualMemory) {
                std::cerr << "Failed to get address of NtAllocateVirtualMemory." << std::endl;
                return;
            }

            if (!NtAllocateVirtualMemory) {
                std::cerr << "Failed to get address of NtAllocateVirtualMemory." << std::endl;
                return;
            }
            
            if (!LdrLoadDllFunc) {
                std::cerr << "Failed to get address of LdrLoadDll." << std::endl;
                return;
            }

           
            break;
        }

        std::wcout << L"found:" << dllName << std::endl;

    }
}

int main() {
    FindNtdll();
    return 0;
}
