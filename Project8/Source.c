#include<stdio.h>
#include<windows.h>
#include<tchar.h>
#pragma warning (disable : 4996)
char *command = "C:\\Windows\\System32\\calc.exe";

typedef struct INJECT_ARGV {
	FARPROC func[10];
	char argv[5][5];
	int size[1];

}INJECT_ARGV;

DWORD WINAPI ThreadProc_Injection(INJECT_ARGV *t) 
{

	HANDLE(__stdcall *proc)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
	proc = (HANDLE(__stdcall *)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE))t->func[0];
	HANDLE hFile = proc(t->argv[0], GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

	HANDLE(__stdcall *proc2)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
	proc2 = (HANDLE(__stdcall *)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED))t->func[1];
	proc2(hFile, "code_injection", 15, 0, NULL);

}

void func() {

}

int main(int argc, char **argv) {
	INJECT_ARGV inject;
	STARTUPINFO si = { 0, };
	PROCESS_INFORMATION pi;
	DWORD pid, bufSize = 0;
	HANDLE cProcess, hThread;
	LPVOID vMemory[2] = {0, };
	si.cb = sizeof(STARTUPINFO);
	
	CreateProcess((LPCSTR)command,
					NULL,
					NULL,
					NULL,
					FALSE,
					0,
					NULL,
					NULL,
					&si,
					&pi);

	pid = pi.dwProcessId;

	cProcess = OpenProcess(PROCESS_ALL_ACCESS,
							FALSE,
							pid);

	HMODULE hMod = LoadLibrary("msvcrt.dll");
	HMODULE hsibal = LoadLibrary(_T("kernel32.dll"));
	
	memset(&inject, '\x00', sizeof(INJECT_ARGV));
	inject.func[0] = GetProcAddress(hsibal, _T("CreateFileA"));
	inject.func[1] = GetProcAddress(hsibal, _T("WriteFile"));

	strcpy(inject.argv[0], ("C:\\Users\\Sim\\Desktop\\dd.txt"));

	bufSize = sizeof(INJECT_ARGV);

	vMemory[0] = VirtualAllocEx(cProcess,
		NULL,
		bufSize,
		MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(cProcess,
		vMemory[0],
		(LPVOID)&inject,
		bufSize,
		NULL);

	bufSize = (DWORD)func - (DWORD)ThreadProc_Injection;
	
	vMemory[1] = VirtualAllocEx(cProcess,
		NULL,
		bufSize,
		MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(cProcess,
		vMemory[1],
		(LPVOID)ThreadProc_Injection,
		bufSize,
		NULL);

	hThread = CreateRemoteThread(cProcess,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)vMemory[1],
		vMemory[0],
		0,
		NULL);


	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(cProcess);

}

