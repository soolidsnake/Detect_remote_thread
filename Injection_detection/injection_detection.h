#include "pch.h"

#define MAX_FILENAME_LENGTH 512
#define PRIORITY_BOOSTER_DEVICE 0x8000
#define IOCTL_INJECTION_DUMP CTL_CODE(PRIORITY_BOOSTER_DEVICE, \
0x800, METHOD_NEITHER, FILE_ANY_ACCESS)

struct Shellcode {
	USHORT Size;
	LARGE_INTEGER Time;
	ULONG ThreadId;
	ULONG ProcessId;
	WCHAR name[MAX_FILENAME_LENGTH];
};

template<typename T>
struct FullItem {
	LIST_ENTRY Entry;
	T Data;
};

struct Globals {
	LIST_ENTRY ItemsHead;
	int ItemCount;
	FastMutex Mutex;
};

struct FILENAME {
	WCHAR path[128];
	FastMutex Mutex;
};



typedef NTSTATUS(*QUERY_INFO_PROCESS) (
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
	);


QUERY_INFO_PROCESS ZwQueryInformationProcess;

typedef NTSTATUS(*QUERY_INFO_THREAD)(
	IN HANDLE          ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	OUT PVOID          ThreadInformation,
	IN ULONG           ThreadInformationLength,
	OUT PULONG         ReturnLength
	);

QUERY_INFO_THREAD NtQueryInformationThread;
