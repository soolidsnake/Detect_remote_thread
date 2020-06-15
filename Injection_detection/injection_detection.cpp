#include "pch.h"
#include "FastMutex.h"
#include "AutoLock.h"
#include "ntifs.h"
#include "ntstrsafe.h"
#include "injection_detection.h"
//#include <ntifs.h>
#include <string.h>

#define DRIVER_PREFIX "injection_detection: "
#define DRIVER_TAG 'eee'

NTSTATUS injection_detectionCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS injection_detectionRead(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS injection_detectionWrite(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS injection_detectionControlDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
void injection_detectionUnload(_In_ PDRIVER_OBJECT DriverObject);
void PushItem(LIST_ENTRY* entry);

void OnThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create);


NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG_PTR info = 0)
{
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

Globals g_Globals;

FILENAME filename;

// DriverEntry
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	PDEVICE_OBJECT DeviceObject;
	//PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine;

	UNREFERENCED_PARAMETER(RegistryPath);
	DriverObject->MajorFunction[IRP_MJ_CREATE] = injection_detectionCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = injection_detectionCreateClose;
	DriverObject->MajorFunction[IRP_MJ_READ] = injection_detectionRead;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = injection_detectionWrite;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = injection_detectionControlDevice;
	DriverObject->DriverUnload = injection_detectionUnload;

	InitializeListHead(&g_Globals.ItemsHead);
	g_Globals.Mutex.Init();
	filename.Mutex.Init();

	status = PsSetCreateThreadNotifyRoutine(OnThreadNotify);

	if (!NT_SUCCESS(status)) {
		KdPrint((DRIVER_PREFIX "failed to register process callback (0x%08X)\n", status));
	}

	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\injection_detection");
	status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, TRUE, &DeviceObject);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Failed to create device object (0x%08)\n", status));
		return status;
	}
	// set up Direct I/O
	DeviceObject->Flags |= DO_DIRECT_IO;

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\injection_detection");
	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Failed to create symbolic link (0x%08X)\n", status));
		IoDeleteDevice(DeviceObject);
		return status;
	}

	filename.Mutex.Lock();
	RtlStringCchPrintfW(filename.path, 128, L"C:\\");
	filename.Mutex.Unlock();
	KdPrint(("finished driverentry"));

	return STATUS_SUCCESS;
}


NTSTATUS injection_detectionCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	return CompleteIrp(Irp, STATUS_SUCCESS);
}


NTSTATUS injection_detectionRead(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	auto stack = IoGetCurrentIrpStackLocation(Irp);
	auto len = stack->Parameters.Read.Length;
	auto buff = (UCHAR*)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

	if (!buff)
		return CompleteIrp(Irp, STATUS_INSUFFICIENT_RESOURCES);

	//AutoLock<FastMutex> lock(g_Globals.Mutex);

	g_Globals.Mutex.Lock();

	int count = 0;

	while (TRUE)
	{
		if (IsListEmpty(&g_Globals.ItemsHead))
			break;

		auto entry = RemoveHeadList(&g_Globals.ItemsHead);
		auto info = CONTAINING_RECORD(entry, FullItem<Shellcode>, Entry);
		auto size = info->Data.Size;
		if (len < size)
		{
			// user's buffer is full, insert item back
			InsertHeadList(&g_Globals.ItemsHead, entry);
			break;
		}
		len -= size;
		count += size;



		::memcpy(buff, &info->Data, info->Data.Size);




		buff += size;
		ExFreePool(info);
	}
	
	
	g_Globals.Mutex.Unlock();


	return CompleteIrp(Irp, STATUS_SUCCESS, count);
}


NTSTATUS write_file(PVOID kshellcode, SIZE_T RegionSize, WCHAR wbuff[])
{

	UNICODE_STRING     uniName;
	OBJECT_ATTRIBUTES  objAttr;


	RtlInitUnicodeString(&uniName, wbuff);
	InitializeObjectAttributes(&objAttr, &uniName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	HANDLE   handle;
	NTSTATUS ntstatus;
	IO_STATUS_BLOCK    ioStatusBlock;

	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		KdPrint(("oops not passive level %hhx", KeGetCurrentIrql()));
		return STATUS_INVALID_DEVICE_STATE;

	}
	ntstatus = ZwCreateFile(&handle,
		GENERIC_WRITE,
		&objAttr, &ioStatusBlock, NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);


	#define  BUFFER_SIZE 30
	CHAR     buffer[BUFFER_SIZE];
	ULONG  cb;


	if (NT_SUCCESS(ntstatus))
	{
		ntstatus = RtlStringCbPrintfA(buffer, sizeof(buffer), "This is %d test\r\n", 0x0);
		if (NT_SUCCESS(ntstatus)) {
			ntstatus = RtlStringCbLengthA(buffer, sizeof(buffer), (size_t*)&cb);
			if (NT_SUCCESS(ntstatus)) {
				KdPrint(("writing"));
				ntstatus = ZwWriteFile(handle, NULL, NULL, NULL, &ioStatusBlock,
					kshellcode, (ULONG)RegionSize, NULL, NULL);
			}
		}
		ZwClose(handle);
		KdPrint(("finished writing"));
	}

	return STATUS_SUCCESS;
}


NTSTATUS injection_detectionWrite(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	return CompleteIrp(Irp, STATUS_SUCCESS, 0);
}


NTSTATUS injection_detectionControlDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	auto stack = IoGetCurrentIrpStackLocation(Irp);
	auto len = stack->Parameters.Read.Length;

	KdPrint(("%ws", stack->Parameters.DeviceIoControl.Type3InputBuffer));

	auto buff = stack->Parameters.DeviceIoControl.Type3InputBuffer;
	buff;

	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_INJECTION_DUMP:
	{
		filename.Mutex.Lock();
		::memcpy(filename.path, buff, 128);
		filename.Mutex.Unlock();

		KdPrint(("new path %ws", filename.path));
		
		return CompleteIrp(Irp, STATUS_SUCCESS, 0);
		break;
	}
	default:
		return CompleteIrp(Irp, STATUS_INVALID_DEVICE_REQUEST);
		break;
	}
}


void injection_detectionUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	KdPrint(("Driver unloaded\n"));
	PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\injection_detection");
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);
}


void OnThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
	OBJECT_ATTRIBUTES ObjectAttributes;
	HANDLE handle;
	InitializeObjectAttributes(&ObjectAttributes, nullptr, 0, 0, nullptr);
	CLIENT_ID ClientId = {};
	ClientId.UniqueProcess = ProcessId;
	ClientId.UniqueThread = ThreadId;
	auto status = ZwOpenProcess(&handle, READ_CONTROL, &ObjectAttributes, &ClientId);

	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "Failed to open process\n"));
		return;
	}
	if (!Create)
		return;
	PROCESS_BASIC_INFORMATION  ProcessInformation;
	ULONG ReturnLength;
	UNICODE_STRING ZwQueryInformationProcessName, NtQueryInformationThreadName;

	if (ZwQueryInformationProcess == nullptr)
	{
		RtlInitUnicodeString(&ZwQueryInformationProcessName, L"ZwQueryInformationProcess");
		RtlInitUnicodeString(&NtQueryInformationThreadName, L"ZwQueryInformationThread");

		ZwQueryInformationProcess = (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&ZwQueryInformationProcessName);


		NtQueryInformationThread = (QUERY_INFO_THREAD)MmGetSystemRoutineAddress(&NtQueryInformationThreadName);


		if (ZwQueryInformationProcess == nullptr)
		{
			DbgPrint("Cannot resolve ZwQueryInformationProcess\n");
			ZwClose(handle);
			return;
		}

		if (NtQueryInformationThread == nullptr)
		{
			DbgPrint("Cannot resolve ZwQueryThreadInformation\n");
			ZwClose(handle);
			return;
		}
	}
	status = ZwQueryInformationProcess(handle, ProcessBasicInformation, &ProcessInformation, sizeof(ProcessInformation), &ReturnLength);

	auto currentPid = PsGetCurrentProcessId();


	if (!(ProcessInformation.InheritedFromUniqueProcessId != HandleToUlong(currentPid) && HandleToULong(ProcessId) != HandleToUlong(currentPid))){
		return;
	}


	KdPrint(("Injection of thread %d on %d \n", HandleToULong(ThreadId), HandleToUlong(ProcessId)));
	PVOID ThreadInformation;


	PETHREAD peThread;

	status = PsLookupThreadByThreadId(ThreadId, &peThread);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("failed PsLookupThreadByThreadId (0x%08X)\n", status));
		ZwClose(handle);
		return;
	}

	HANDLE hThreadRef;
	status = ObOpenObjectByPointer(peThread, OBJ_KERNEL_HANDLE, NULL, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, &hThreadRef);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("failed ObOpenObjectByPointer (0x%08X)\n", status));
		ZwClose(handle);
		return;
	}

	status = NtQueryInformationThread(hThreadRef, ThreadQuerySetWin32StartAddress, &ThreadInformation, sizeof(PVOID), &ReturnLength);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("failed QueryThreadInformation (0x%08X)\n", status));
		ZwClose(handle);
		return;
	}
	KdPrint(("Start address is : %p", ThreadInformation));

	KAPC_STATE* Apcstate;
	PEPROCESS eProcess;

	Apcstate = (KAPC_STATE*)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC_STATE), DRIVER_TAG);
	if (Apcstate == nullptr)
	{
		KdPrint(("Error allocate apcstate"));
		ZwClose(handle);
		return;
	}

	status = PsLookupProcessByProcessId(ProcessId, &eProcess);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("failed PsLookupProcessByProcessId (0x%08X)\n", status));
		ZwClose(handle);
		return;
	}


	auto info = (FullItem<Shellcode>*)ExAllocatePoolWithTag(PagedPool, sizeof(FullItem<Shellcode>), DRIVER_TAG);
	if (info == nullptr) {
		KdPrint((DRIVER_PREFIX "Failed to allocate memory\n"));
		return;
	}
	info->Data.Size = sizeof(Shellcode);
	KeQuerySystemTimePrecise(&info->Data.Time);
	info->Data.ThreadId= HandleToULong(ThreadId);
	info->Data.ProcessId = HandleToULong(ProcessId);

	KeStackAttachProcess(eProcess, Apcstate);

	KdPrint(("shellcode: %p", (int)*(UCHAR*)ThreadInformation));

	MEMORY_BASIC_INFORMATION mem = {0};
	SIZE_T i;
	NTSTATUS t;

	HANDLE hProcessRef;
	PEPROCESS peProcess;

	status = PsLookupProcessByProcessId(ProcessId, &peProcess);
	status = ObOpenObjectByPointer(peProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hProcessRef);

	t = ZwQueryVirtualMemory(hProcessRef, ThreadInformation, MemoryBasicInformation, &mem, sizeof(mem), &i);

	if (!NT_SUCCESS(t))	{
		KdPrint(("problem query %x\n", t));
	}

	PVOID kshellcode = nullptr;
	kshellcode = ExAllocatePoolWithTag(PagedPool, mem.RegionSize, DRIVER_TAG);
	if(!kshellcode)
		::memcpy(kshellcode, mem.AllocationBase, mem.RegionSize);

	ExFreePool(Apcstate);
	ObDereferenceObject(eProcess);
	KeUnstackDetachProcess(Apcstate);
	ZwClose(handle);

	WCHAR wbuff[MAX_FILENAME_LENGTH];

	filename.Mutex.Lock();


	RtlStringCchPrintfW(wbuff, MAX_FILENAME_LENGTH, L"\\DosDevices\\%ws\\time_%I64d_ProcessId_%d_threadId_%d", filename.path, info->Data.Time, ProcessId, ThreadId);


	filename.Mutex.Unlock();

	KdPrint(("after unlock"));

	KdPrint(("name: %ws", wbuff));

	if (kshellcode != nullptr) 
	{
		write_file(kshellcode, mem.RegionSize, wbuff);
		ExFreePool(kshellcode);
	}
	::memcpy(info->Data.name, wbuff, MAX_FILENAME_LENGTH);	
	
	PushItem(&info->Entry);
}


void PushItem(LIST_ENTRY* entry)
{
	AutoLock<FastMutex> lock(g_Globals.Mutex);
	if (g_Globals.ItemCount > 1024)
	{
		// too many items, remove oldest one
		auto head = RemoveHeadList(&g_Globals.ItemsHead);
		g_Globals.ItemCount--;
		auto item = CONTAINING_RECORD(head, FullItem<Shellcode>, Entry);
		ExFreePool(item);
	}
	InsertTailList(&g_Globals.ItemsHead, entry);
	g_Globals.ItemCount++;
}