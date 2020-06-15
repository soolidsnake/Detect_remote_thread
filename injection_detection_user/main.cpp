#include "main.h"
#include <stdio.h>
#include <Windows.h>
#include <stdlib.h>

void Error(const char* msg) {
	printf("%s: error=%d\n", msg, ::GetLastError());
}


void set_path(HANDLE hDevice, CHAR* path)
{
	DWORD returned;

	WCHAR wpath[128];
	size_t i;
	mbstowcs_s(&i, wpath, path, sizeof(wpath));

	printf("path %ws\n", wpath);
	printf("path %s\n", path);

	BOOL success = DeviceIoControl(hDevice, IOCTL_INJECTION_DUMP, wpath, 128, path, 128, &returned, nullptr);

	if (success)
		printf("ioctl worked\n");
}


void read_driver(HANDLE hDevice)
{


	BYTE buffer[1 << 16] = { 0 };

	DWORD bytes;

	BOOL ok = ::ReadFile(hDevice, buffer, sizeof(buffer), &bytes, nullptr);
	if (!ok)
		return Error("failed to read");

	int len = 0;

	printf("bytes => %d\n\n", bytes);
	while (TRUE)
	{
		if (len >= bytes)
			break;
		auto data = (Shellcode*)(buffer + len);
		len += data->Size;

		int i = 0;
		printf("shellcode injected in process %d, executed by thread %d\n", data->ProcessId, data->ThreadId);

		wprintf(L"\nname %ws\n", data->name);


		printf("\n\n");
		Sleep(2000);
	}
}


void  main(int argc, char **argv)
{
	if (argc < 2)
		exit(-1);
	

	HANDLE hDevice = ::CreateFile(L"\\\\.\\injection_detection", GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

	if (hDevice == nullptr) {
		return Error("CreateFile failed\n");
	}

	char* endptr;
	int x = strtol(argv[1], &endptr, 10);

	if(x == 0)
		read_driver(hDevice);
	if (x == 1)
		set_path(hDevice, argv[2]);
	   
	CloseHandle(hDevice);
}