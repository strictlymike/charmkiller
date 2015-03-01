// File: charmkiller.cpp
// Author: Michael Bailey
// License: WTFPL - http://www.wtfpl.net/
//
// Adapted from MSDN:
// https://msdn.microsoft.com/en-us/library/windows/desktop/ms682621%28v=vs.85%
// 29.aspx
// And from "How to get the module name associated with a thread" (Rohitab):
// http://www.rohitab.com/discuss/topic/36675-how-to-get-the-module-name-associ
// ated-with-a-thread/

#include <windows.h>
#include <Tlhelp32.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>

// TODO: To ensure correct symbol resolution, compile with -DPSAPI_VERSION=1
#pragma comment(lib, "psapi.lib")

#define CONFIG_IMMASCULATE		0
#define STATUS_SUCCESS			((NTSTATUS)0x00000000L)
#define STATUS_ACCESS_IS_DENIED ((NTSTATUS)0x00000005L)
#define IMMERSIVE_SHELL_DLL		"windows.immersiveshell.serviceprovider.dll"
#define EXPLORER_EXE			"explorer.exe"
#define ThreadQuerySetWin32StartAddress	9

struct ThreadSpec
{
	DWORD Pid;
	HANDLE hProcess;
	ULONG_PTR StartAddress;
	ULONG_PTR EndAddress;
	HMODULE hModule;
};

typedef NTSTATUS (WINAPI *NTQUERYINFOMATIONTHREAD)(
	HANDLE,
	LONG,
	PVOID,
	ULONG,
	PULONG
   );

BOOL InitializeFuncPtrs(void);
int strchr_rev(char *stack, char needle);
char *FinalComponent(char *name);
int FinalComponentIs(char *path, char *name);
BOOL AllocAndEnumProcs(DWORD **Pids, int *PidsLen);
template <class T> BOOL _AllocAndEnumItems(
	T **Array,
	int *Count,
	HANDLE hProc=NULL
   );
HANDLE FindProc(DWORD *Pids, int PidsLen, char *ProcNameSought);
HMODULE FindMod(HANDLE hProc, char *ModNameSought);
HANDLE FindThread(HANDLE hProc, HMODULE hModImm);

// Globals
NTQUERYINFOMATIONTHREAD NtQueryInformationThread;

int
main(void)
{
	int ret = 1;
	BOOL Okay;
	DWORD *Pids;
	int PidsLen;
	DWORD Pid, Tid;
	HANDLE hProc, hThread;
	HMODULE hModImm;

	if (!InitializeFuncPtrs())
	{
		fprintf(
			stderr,
			"Failed to initialize function pointers, GLE=%d\n",
			GetLastError()
		   );
		goto end;
	}

	if (!AllocAndEnumProcs(&Pids, &PidsLen))
	{
		fprintf(stderr, "Failed to allocate space and enumerate processes\n");
		goto end;
	}

	hProc = FindProc(Pids, PidsLen, EXPLORER_EXE);
	if (hProc == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "Failed to find %s\n", EXPLORER_EXE);
		goto end;
	}

	Pid = GetProcessId(hProc);
	printf("Located %s(%d)\n", EXPLORER_EXE, Pid);

	hModImm = FindMod(hProc, IMMERSIVE_SHELL_DLL);
	if (hModImm == 0)
	{
		fprintf(stderr, "Failed to find %s\n", IMMERSIVE_SHELL_DLL);
		goto end;
	}

	printf("Located %s(0x%08X)\n", IMMERSIVE_SHELL_DLL, hModImm);

	hThread = FindThread(hProc, hModImm);

	if (hThread == NULL)
	{
		fprintf(stderr, "Failed to find thread\n");
		goto end;
	}

	Tid = GetThreadId(hThread);

	if (!TerminateThread(hThread, 1))
	{
		fprintf(
			stderr,
			"Failed to terminate thread, GLE=%d\n",
			GetLastError()
		   );
		goto end;
	}

	printf("Terminated thread %d\n", Tid);

end:
	return ret;
}

// Link to NtQueryInformationThread()
BOOL
InitializeFuncPtrs(void)
{
	HMODULE hNtdll;

	hNtdll = LoadLibrary("ntdll.dll");
	if (hNtdll == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	NtQueryInformationThread = (NTQUERYINFOMATIONTHREAD) GetProcAddress(
		LoadLibrary("ntdll.dll"),
		"NtQueryInformationThread"
	   );

	if (NtQueryInformationThread == NULL)
	{
		return FALSE;
	}

	return TRUE;
}

BOOL
AllocAndEnumProcs(DWORD **Pids, int *PidsLen)
{
	return _AllocAndEnumItems<DWORD>(Pids, PidsLen);
}

BOOL AllocAndEnumModules(HANDLE hProc, HMODULE **Mods, int *ModsLen)
{
	return _AllocAndEnumItems<HMODULE>(Mods, ModsLen, hProc);
}

// Allocate progressively larger PID/HMODULE arrays up to Limit elements and
// repeatedly call EnumProcesses() / EnumProcessModules() to populate with the
// current list of PIDs/modules.  In practice, 1024 is enough for the "Works On
// My Machine" level of quality, but I'm self-conscious about code that others
// may see.
template <class T>
BOOL
_AllocAndEnumItems(T **Array, int *Count, HANDLE hProc)
{
	const int ArrayLen0 = 1024;
	const int MaxLen = 32768;
	DWORD Size, Needed;
	BOOL Okay, Ret;

	Ret = FALSE;
	*Count = ArrayLen0;

	while (1)
	{
		Size = *Count * sizeof(T);
		*Array = (T *)LocalAlloc(0, Size);
		if (*Array == NULL)
		{
			break;
		}

		// Casts are used to make these subtly different functions coexist in
		// the template situations that they are NOT used for (HMODULE vs
		// DWORD).
		if (hProc != NULL) {
			Okay = EnumProcessModules(hProc, (HMODULE *)*Array, Size, &Needed);
		} else {
			Okay = EnumProcesses((DWORD *)*Array, Size, &Needed);
		}

		if (!Okay)
		{
			break;
		}

		if (Needed < Size)
		{
			Ret = TRUE;
			*Count = Needed / sizeof(T);
			break;
		}

		// Set up for next resized allocation
		LocalFree(*Array);
		*Count += ArrayLen0;

		if (*Count > MaxLen)
		{
			break;
		}
	}

	return Ret;
}

HANDLE
FindProc(DWORD *Pids, int PidsLen, char *ProcNameSought)
{
	HANDLE hProc;
	HANDLE Ret = INVALID_HANDLE_VALUE;
	DWORD Len;
	int i;
	char Name[MAX_PATH];

	// For each process...
	for (i=0; i<PidsLen; i++)
	{
		// Pop it open
		hProc = OpenProcess(
			PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			FALSE,
			Pids[i]
		   );

		// If a given process cannot be opened, move on to the next
		if ((hProc == NULL) || (hProc == INVALID_HANDLE_VALUE)) { continue; }

		// Get the filename
		Len = GetProcessImageFileName(hProc, Name, MAX_PATH);

		// If a given process filename cannot be obtained, move on to the next
		if (Len == 0) { continue; }

		// If the process name is not what was sought, move on to the next
		if (FinalComponentIs(Name, ProcNameSought))
		{
			Ret = hProc;
			break;
		}
	}

	return Ret;
}

HMODULE
FindMod(HANDLE hProc, char *ModNameSought)
{
	HMODULE *Mods;
	int ModsLen;
	BOOL Okay;
	int i;
	TCHAR szModName[MAX_PATH];
	HMODULE Ret = 0;

	Okay = AllocAndEnumModules(hProc, &Mods, &ModsLen);

	if (Okay)
	{
		for (i=0; i<ModsLen; i++)
		{
			Okay = GetModuleFileNameEx(
				hProc,
				Mods[i],
				szModName,
				sizeof(szModName) / sizeof(TCHAR)
			   );

			if (!Okay)
			{
				continue;
			}

			if (FinalComponentIs(szModName, ModNameSought))
			{
				Ret = Mods[i];
				break;
			}
		}
	}

	return Ret;
}

HANDLE
FindThread(HANDLE hProc, HMODULE hModImm)
{
	ULONG_PTR Start, End;
	MODULEINFO ModInfo;
	HANDLE hSnapshot, hThread, Ret;
	DWORD Pid;
	THREADENTRY32 Thread = {0};
	ULONG_PTR ThreadEntryAddr;
	NTSTATUS Status;

	Ret = hSnapshot = hThread = INVALID_HANDLE_VALUE;

	if (!GetModuleInformation(hProc, hModImm, &ModInfo, sizeof(ModInfo)))
	{
		goto end;
	}

	// Query bounds for thread classification
	Start = (ULONG_PTR) ModInfo.lpBaseOfDll;
	End = (ULONG_PTR) ModInfo.lpBaseOfDll + ModInfo.SizeOfImage;

	Pid = GetProcessId(hProc);
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, Pid);

	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		goto end;
	}

	Thread.dwSize = sizeof(Thread);
	Thread.cntUsage = 0;

	// TODO: confirm usage and verify return
	if (!Thread32First(hSnapshot, &Thread))
	{
		goto end;
	}

	do
	{
		// Note to self: why is it necessary to check this.  Why is the PID
		// specified in the call to CreateToolhelp32Snapshot() not the only PID
		// that appears in its results?
		if (Thread.th32OwnerProcessID == Pid)
		{
			hThread = OpenThread(
#if CONFIG_IMMASCULATE
				THREAD_QUERY_INFORMATION,
#else
				THREAD_ALL_ACCESS,
#endif
				FALSE,
				Thread.th32ThreadID
			   );
			if (hThread == INVALID_HANDLE_VALUE)
			{
				// Move on to the next
				continue;
			}

			// https://msdn.microsoft.com/en-us/library/windows/desktop/ms68428
			// 3%28v=vs.85%29.aspx
			Status = NtQueryInformationThread(
				hThread,
				ThreadQuerySetWin32StartAddress,
				&ThreadEntryAddr,
				sizeof(ThreadEntryAddr),
				NULL
			);

			if (Status != STATUS_SUCCESS)
			{
				// Move on to the next
				continue;
			}

			if ((ThreadEntryAddr >= Start) && (ThreadEntryAddr < End))
			{
				Ret = hThread;
				break;
			}
		}
	}
	while (Thread32Next(hSnapshot, &Thread));

end:
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hSnapshot);
	}

	return hThread;
}

// I didn't think I'd have to implement this, but as far as I could tell at the
// time, it doesn't exist.
int
strchr_rev(char *stack, char needle)
{
	size_t len;
	int i;

	len = strlen(stack);

	for (i=len-1; i>0; i--)
	{
		if (stack[i] == needle)
		{
			return i;
		}
	}

	return -1;
}

char
*FinalComponent(char *name)
{
	int slash;
	char *ret = name;
	
	slash = strchr_rev(name, '\\');

	if (slash != -1)
	{
		ret = (name + slash + 1);
	}

	return ret;
}

int
FinalComponentIs(char *path, char *name)
{
	return (stricmp(FinalComponent(path), name) == 0);
}
