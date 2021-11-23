#include <windows.h>
#include <stdio.h>
#include "headers/beacon.h"
#include "headers/internal_structs.h"
#include "headers/internal.h"
#include "headers/win32.h"


//Taken from : https://newbedev.com/c-library-to-read-exe-version-from-linux
#define READ_BYTE(p) (((unsigned char*)(p))[0])
#define READ_WORD(p) ((((unsigned char*)(p))[0]) | ((((unsigned char*)(p))[1]) << 8))
#define READ_DWORD(p) ((((unsigned char*)(p))[0]) | ((((unsigned char*)(p))[1]) << 8) | \
    ((((unsigned char*)(p))[2]) << 16) | ((((unsigned char*)(p))[3]) << 24))

#define PAD(x) (((x) + 3) & 0xFFFFFFFC)


// Forward declarations
int PrintVersion (formatp* format, const char* version, int offs);
VOID ParseResource (formatp* format, HMODULE hMod);
VOID FindLoadedDllsCurrentProcess (formatp* format, int verbose);
VOID FindLoadedDllsCurrentProcessWithNeedle(formatp* formatObject, int verbose, const wchar_t* needle);
int Orchestrate (char* args, int arglength);
int OrchestrateWithNeedle (char* args, int arglength);
void DumpFormatStructContents (formatp* format);


// Implementations
void DumpFormatStructContents(formatp* format)
{
    char*   outputString = NULL;
    int     sizeOfObject = 0;

    outputString = BeaconFormatToString(format, &sizeOfObject);

    BeaconOutput(CALLBACK_OUTPUT, outputString, sizeOfObject);
    BeaconFormatFree(format);

    return;
}


int PrintVersion(formatp* format, const char* version, int offs)
{
    offs = PAD(offs);
    WORD len = READ_WORD(version + offs);
    offs += 2;
    WORD valLen = READ_WORD(version + offs);
    offs += 2;
    WORD type = READ_WORD(version + offs);
    offs += 2;
    char info[200];
    int i;
    for (i = 0; i < 200; ++i)
    {
        WORD c = READ_WORD(version + offs);
        offs += 2;

        info[i] = c;
        if (!c)
            break;
    }

    offs = PAD(offs);
    
    if (type != 0) //TEXT
    {
        char value[200];
        for (i = 0; i < valLen; ++i)
        {
            WORD c = READ_WORD(version + offs);
            offs += 2;
            value[i] = c;
        }
        value[i] = 0;
        if (strlen(info) > 0)
        {
            //This is an identifer in memory, no need to print it
            if (MSVCRT$_stricmp(info, "040904b0") != 0)
            {
                BeaconFormatPrintf(format, "%s:\t%s\n", info, value);
            }
        }
    }
    else
    {
        if (MSVCRT$_stricmp(info, "VS_VERSION_INFO") == 0)
        {
            //fixed is a VS_FIXEDFILEINFO
            const char* fixed = version + offs;
            WORD fileA = READ_WORD(fixed + 10);
            WORD fileB = READ_WORD(fixed + 8);
            WORD fileC = READ_WORD(fixed + 14);
            WORD fileD = READ_WORD(fixed + 12);
            WORD prodA = READ_WORD(fixed + 18);
            WORD prodB = READ_WORD(fixed + 16);
            WORD prodC = READ_WORD(fixed + 22);
            WORD prodD = READ_WORD(fixed + 20);

            BeaconFormatPrintf(format, "File version:\t%d.%d.%d.%d\n", fileA, fileB, fileC, fileD);
            BeaconFormatPrintf(format, "Prod version:\t%d.%d.%d.%d\n", prodA, prodB, prodC, prodD);
        }
        offs += valLen;
    }
    
    while (offs < len)
    {
        offs = PrintVersion(format, version, offs);
    }

    return PAD(offs);
}


//Find the resources in each module
VOID ParseResource(formatp* format, HMODULE hMod)
{
    char* pBaseAddr = (char*)hMod;

    IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pBaseAddr;
    IMAGE_NT_HEADERS* pNTHdr = (IMAGE_NT_HEADERS*)(pBaseAddr + pDosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER* pOptionalHdr = &pNTHdr->OptionalHeader;

    // Parsing resource data
    IMAGE_DATA_DIRECTORY* pResourceDir = &pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    IMAGE_RESOURCE_DIRECTORY* resSec = (IMAGE_RESOURCE_DIRECTORY*)(pBaseAddr + pResourceDir->VirtualAddress);

    if (resSec == NULL) return;
    size_t namesNum = resSec->NumberOfNamedEntries;
    size_t idsNum = resSec->NumberOfIdEntries;
    size_t totalEntries = namesNum + idsNum;

    IMAGE_RESOURCE_DIRECTORY_ENTRY* typeEntry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(resSec + 1);

    //Iterate through all resources checking type
    for (size_t i = 0; i < totalEntries; i++) {

        //16 == RT_VERSION
        if (typeEntry[i].Id == 16)
        {
            //If it isn't a directory, something went wrong
            if (typeEntry[i].DataIsDirectory == 0)
                return;

            DWORD offset = typeEntry[i].OffsetToDirectory;

            //Get the offset to the version directory
            IMAGE_RESOURCE_DIRECTORY* versionDirectory = (IMAGE_RESOURCE_DIRECTORY*)(pBaseAddr + pResourceDir->VirtualAddress + (offset & 0x7FFFFFFF));

            size_t namesNum_ver = versionDirectory->NumberOfNamedEntries;
            size_t idsNum_ver = versionDirectory->NumberOfIdEntries;
            size_t totalEntries_ver = namesNum_ver + idsNum_ver;

            
            IMAGE_RESOURCE_DIRECTORY_ENTRY* et_ver = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(versionDirectory + 1);

            //Next level down to get the language entry
            if (et_ver->DataIsDirectory == 1)
            {
                offset = et_ver->OffsetToDirectory;
                IMAGE_RESOURCE_DIRECTORY* langDir = (IMAGE_RESOURCE_DIRECTORY*)(pBaseAddr + pResourceDir->VirtualAddress + (offset & 0x7FFFFFFF));

                size_t namesNum_lang = langDir->NumberOfNamedEntries;
                size_t idsNum_lang = langDir->NumberOfIdEntries;
                size_t totalEntries_lang = namesNum_lang + idsNum_lang;

                IMAGE_RESOURCE_DIRECTORY_ENTRY* et_lang = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(langDir + 1);

                offset = et_lang->OffsetToData;

                //Actual resource entry
                PIMAGE_RESOURCE_DATA_ENTRY resource = (PIMAGE_RESOURCE_DATA_ENTRY)(pBaseAddr + pResourceDir->VirtualAddress + (offset & 0x7FFFFFFF));
                LPVOID rsrc_data = (LPVOID)(pBaseAddr + (resource->OffsetToData));
                DWORD rsrc_size = resource->Size;

                //Don't need the size because we are manually parsing memory
                PrintVersion(format, (const char*)rsrc_data, 0);
            }
        }
    }
}


VOID FindLoadedDllsCurrentProcess(formatp* formatObject, int verbose) 
{
    // get the offset of Process Environment Block
    #ifdef _M_IX86 
        mPEB* ProcEnvBlk = (mPEB*)__readfsdword(0x30);
    #else
        mPEB* ProcEnvBlk = (mPEB*)__readgsqword(0x60);
    #endif

    mPEB_LDR_DATA* Ldr = ProcEnvBlk->Ldr;
    LIST_ENTRY* ModuleList = NULL;

    ModuleList = &Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* pStartListEntry = ModuleList->Flink;

    int index = 1;

    for (LIST_ENTRY* pListEntry = pStartListEntry;
        pListEntry != ModuleList;
        pListEntry = pListEntry->Flink) {

        // get current Data Table Entry
        mLDR_DATA_TABLE_ENTRY* pEntry = (mLDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY));

        //Skip these
        if (wcharcmp(pEntry->BaseDllName.Buffer, L"ntdll.dll") == 0)
            continue;
        if (wcharcmp(pEntry->BaseDllName.Buffer, L"kernel32.dll") == 0)
            continue;
        if (wcharcmp(pEntry->BaseDllName.Buffer, L"KERNELBASE.dll") == 0)
            continue;
        if (wcharcmp(pEntry->BaseDllName.Buffer, L"msvcrt.dll") == 0)
            continue;


        //Current module name
        BeaconFormatPrintf(formatObject, "Index:\t\t%02d\n", index);
        BeaconFormatPrintf(formatObject, "Name:\t\t%S\n", (wchar_t*)pEntry->BaseDllName.Buffer);
        
        if (verbose)
        {
            ParseResource(formatObject, (HMODULE)pEntry->DllBase);
            BeaconFormatPrintf(formatObject, "\n\n");
        } else {
            BeaconFormatPrintf(formatObject, "\n");
        }

        index++;
    }
}


VOID FindLoadedDllsCurrentProcessWithNeedle(formatp* formatObject, int verbose, const wchar_t* needle)
{
    // get the offset of Process Environment Block
    #ifdef _M_IX86 
        mPEB* ProcEnvBlk = (mPEB*)__readfsdword(0x30);
    #else
        mPEB* ProcEnvBlk = (mPEB*)__readgsqword(0x60);
    #endif

    mPEB_LDR_DATA* Ldr = ProcEnvBlk->Ldr;
    LIST_ENTRY* ModuleList = NULL;

    ModuleList = &Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* pStartListEntry = ModuleList->Flink;

    int index = 1;

    for (LIST_ENTRY* pListEntry = pStartListEntry;
        pListEntry != ModuleList;
        pListEntry = pListEntry->Flink) {

        // get current Data Table Entry
        mLDR_DATA_TABLE_ENTRY* pEntry = (mLDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY));

        //Skip these
        if (wcharcmp(pEntry->BaseDllName.Buffer, L"ntdll.dll") == 0)
            continue;
        if (wcharcmp(pEntry->BaseDllName.Buffer, L"kernel32.dll") == 0)
            continue;
        if (wcharcmp(pEntry->BaseDllName.Buffer, L"KERNELBASE.dll") == 0)
            continue;
        if (wcharcmp(pEntry->BaseDllName.Buffer, L"msvcrt.dll") == 0)
            continue;


        if (wcharcmp(pEntry->BaseDllName.Buffer, needle) == 0)
        {
            //Current module name
            BeaconFormatPrintf(formatObject, "Index:\t\t%02d\n", index);
            BeaconFormatPrintf(formatObject, "Name:\t\t%S\n", (wchar_t*)pEntry->BaseDllName.Buffer);
            
            if (verbose)
            {
                ParseResource(formatObject, (HMODULE)pEntry->DllBase);
                BeaconFormatPrintf(formatObject, "\n\n");
            } else {
                BeaconFormatPrintf(formatObject, "\n");
            }

            index++;
        }
    }
}


int Orchestrate(char* args, int arglength)
{
    datap parser;
    formatp formatObject;

    int enumerateVerboseInformation;
    
    BeaconDataParse(&parser, args, arglength);
    enumerateVerboseInformation = BeaconDataInt(&parser);

    BeaconFormatAlloc(&formatObject, 64 * 1024);

    FindLoadedDllsCurrentProcess(&formatObject, enumerateVerboseInformation);
    DumpFormatStructContents(&formatObject);

    return 0;    
}


int OrchestrateWithNeedle(char* args, int arglength)
{    
    datap parser;
    formatp formatObject;

    int enumerateVerboseInformation;
    wchar_t* needleToHunt = NULL;

    BeaconDataParse(&parser, args, arglength);
    enumerateVerboseInformation = BeaconDataInt(&parser);
    needleToHunt = (wchar_t*)BeaconDataExtract(&parser, NULL);

    BeaconFormatAlloc(&formatObject, 64 * 1024);

    FindLoadedDllsCurrentProcessWithNeedle(&formatObject, enumerateVerboseInformation, needleToHunt);
    DumpFormatStructContents(&formatObject);

    return 0;
}