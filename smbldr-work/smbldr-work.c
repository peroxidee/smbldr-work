#include <stdio.h>
#include "smbldr-work.h"

typedef struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

using DLLEntry = BOOL(WINAPI*)(HINSTANCE dll, DWORD reason, LPVOID reserved);


int main(int argc, char* argv[]) {

    if (argc < 1) {
        printf("usage: %s <path to dll>", argv[0]);
        return 1;
    }

    CONTEXT ThreadCtx = { .ContextFlags = (CONTEXT_CONTROL | CONTEXT_SEGMENTS | CONTEXT_INTEGER) };

    HANDLE hProc;
    HANDLE hThread;

    size_t mb = GetModHandle(L"C:\\WINDOWS\\System32\\kernel32.dll");

    size_t ptrNAME = (size_t)GetFuncAddr(mb, "NAME");

    size_t ptrCreateFileA = (size_t)GetFuncAddr(mb, "CreateFileA");
    size_t ptrGetModuleHandleA = (size_t)GetFuncAddr(mb, "GetModuleHandleA");
    size_t ptrGetFileSize = (size_t)GetFuncAddr(mb, "GetFileSize");
    size_t ptrHeapAlloc = (size_t)GetFuncAddr(mb, "HeapAlloc");
    size_t ptrGetProccessHeap = (size_t)GetFuncAddr(mb, "GetProccessHeap");
    size_t ptrReadFile = (size_t)GetFuncAddr(mb, "ReadFile");
    size_t ptrVirtAlloc = (size_t)GetFuncAddr(mb, "VirtualAlloc");
    size_t ptrLoadLibraryA = (size_t)GetFuncAddr(mb, "LoadLibraryA");
    size_t ptrCloseHandle = (size_t)GetFuncAddr(mb, "CloseHandle");
    size_t ptrHeapFree = (size_t)GetFuncAddr(mb, "HeapFree");
    size_t ptrReadProcessMemory = (size_t)GetFuncAddr(mb, "ReadProcessMemory");
    size_t ptrGetCurrentProcess = (size_t)GetFuncAddr(mb, "GetCurrentProcess");

    PVOID cimb = ((PVOID(WINAPI*)(LPCSTR))ptrGetModuleHandleA)(NULL);


    HANDLE tdll = ((HANDLE(WINAPI*)(LPCSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE))ptrCreateFileA)(argv[1], GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
    DWORD64 dlsz = ((DWORD64(WINAPI*)(HANDLE, LPDWORD))ptrGetFileSize)(tdll, NULL);
    LPVOID dlbts = ((LPVOID(WINAPI*)(HANDLE, DWORD, SIZE_T))ptrHeapAlloc)(
        ((HANDLE(WINAPI*)())ptrGetProccessHeap)(),
        HEAP_ZERO_MEMORY, dlsz

        );
    DWORD outz = 0;
    ((BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPVOID))ptrReadFile)(tdll, dlbts, &outz, NULL);

    PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)(modb);
    PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(modb + dosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER opH = ntHdr->OptionalHeader;



    SIZE_T dsz = ntHdr->OptionalHeader.SizeOfImage;
    LPVOID = dlb((LPVOID)(WINAPI*)()ptrVirtAlloc)();
    DWORD* dwlb = (DWORD*)dlb;
    DWORD* dltimb = (DWORD*)dlb - (DWORD_PTR)opH.ImageBase;
    memcpy(dlb, );



    IMAGE_DATA_DIRECTORY relocs = opH.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    IMAGE_DATA_DIRECTORY imports = opH.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(ntHdr);
    for (size_t i = 0; i < ntHdr->FileHeader.NumberOfSections; i++)
    {
        LPVOID vda = (LPVOID)(DWORD*)dlb + (DWORD*)sec->VirtualAddress;
        LPVOID szrd = (LPVOID)(DWORD*)dlbts + (DWORD*)sec->PointerToRawData;
        memcpy(vda, szrd, section->SizeOfRawData);
        sec++;

    }

    DWORD* rctbl = relocs.VirtualVaddres + (DWORD*)dlb;
    DWORD relp = 0;
    while (relp < relocs.Size) {
        PBASE_RELOCATION_ENTRY relocb = (PBASE_RELOCATION_ENTRY)(rctbl + relp);
        relp += sizeof(BASE_RELOCATION_BLOCK);
        DWORD relocnt = (relocb->Blocksize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
        PBASE_RELOCATION_ENTRY reloce = (PBASE_RELOCATION_ENTRY)(rctbl + relp);
        for (DWORD i = 0; i < relocnt; i++) {

            relp += sizeof(BASE_RELOCATION_ENTRY);
            if (reloce[i].Type == 0) {
                continue;
            }

            DWORD* relocrva = relocb->PageAddress + reloce[i].Offset;
            DWORD* addr2p = 0;
            ((BOOL(WINAPI*)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T))ptrReadProcessMemory)(

                ((BOOL(WINAPI*)())ptrGetCurrentProccess)(),
                (LPCVOID)(dwlb + relocrva),
                &addr2p,
                sizeof(DWORD*),
                NULL

                );
            addr2p += dltimb;
            memcpy(dwlb + relocrva, addr2p, sizeof(DWORD*));
        }
    }

    PIMAGE_IMPORT_DESCRIPTOR = (PIMAGE_IMPORT_DESCRIPTOR)(imports.VirtualAddress + dwlb);
    LPCSTR libname = "";
    HMODULE lib = NULL;
    while (imports->Name != NULL) {
        libname = (LPCSTR)imports->Name + dwlb;

        wchar_t wlibname[256] = { 0 };
        ((int (WINAPI*)(UINT, DWORD, LPCCH, int, LPWSTR, int))ptrMultiByteToWideChar)(CP_ACP, 0, libname, -1, wlibname, 256);
        size_t mb = GetModHandle(wlibname);

        if (mb != 0) {
            PIMAGE_THUNK_DATA th = NULL;

            th = (PIMAGE_THUNK_DATA)(dwlb + imports->FirstThunk);
            while (th->u1.AddressOfData != NULL) {
                if (IMAGE_SNAP_BY_ORDINAL(th->u1.Ordinal)) {
                    WORD funcord = (WORD)IMAGE_ORDINAL(th->u1.Ordinal);

                    PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)(modb);
                    PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(modb + dosHdr->e_lfanew);
                    IMAGE_OPTIONAL_HEADER opH = ntHdr->OptionalHeader;
                    PIMAGE_EXPORT_DIRECTORY exports = opH.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

                    DWORD* arrf = (DWORD*)(mb + exp->AddressOfFunctions);
                    WORD idx = funcord - (WORD)exports->Base;
                    th->u1.Function = (ULONG_PTR)(mb + arrf[idx]);

                }
                else {
                    PIMAGE_IMPORT_BY_NAME fname = (PIMAGE_IMPORT_BY_NAME)(dwlb + th->u1.AddressOfData);
                    DWORD* funca = (DWORD*)GetFuncAddr(mb, fname->Name);
                    th->u1.Function = funca;
                }
                th++;


            }

        }



        imports++;
    }




    DLLEntry DllEntry = (DllEntry)(dwlb + opH.AddressOfEntryPoint);
    (*DllEntry)((HINSTANCE)dlb, DLL_PROCESS_ATTACH, 0);

    ((BOOL(WINAPI*)(HANDLE))ptrCloseHandle)(tdll);
    ((BOOL(WINAPI*)(HANDLE, DWORD, LPVOID))ptrHeapFree)(((HANDLE(WINAPI*)())ptrGetProccessHeap)(), 0, dlbts);

    return 0;
}
