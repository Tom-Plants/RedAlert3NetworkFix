#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <io.h>
#include <TlHelp32.h>
#include <mhook.h>
#include <process.h>


#pragma comment(lib, "ws2_32.lib")

SOCKET WINAPI Hook_socket(int af, int type, int protocol);



typedef SOCKET(WINAPI* _socket)(int af, int type, int protocol);
_socket TrueSocket = NULL;

SOCKET WINAPI Hook_socket(int af, int type, int protocol)
{
	printf("***** Call to socket(0x%p, 0x%p, 0x%p)\n", af, type, protocol);
	return TrueSocket(af, type, protocol);
}

DWORD GetProcessIDByName(const TCHAR* pName)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot) {
		return NULL;
	}
	PROCESSENTRY32 pe = { sizeof(pe) };
	for (BOOL ret = Process32First(hSnapshot, &pe); ret; ret = Process32Next(hSnapshot, &pe)) {
		if (wcscmp(pe.szExeFile, pName) == 0) {
			CloseHandle(hSnapshot);
			return pe.th32ProcessID;
		}
		//printf("%-6d %s\n", pe.th32ProcessID, pe.szExeFile);
	}
	CloseHandle(hSnapshot);
	return 0;
}

typedef HMODULE(__stdcall *LPLOADLIBRARYA)(LPCSTR);
typedef LPVOID (__stdcall *GETPROCADDRESS)(HMODULE, LPCSTR);
typedef HMODULE (__stdcall *GETMODULEHANDLE)(LPCSTR);
typedef VOID (*MAIN)();

#pragma check_stack (off)
DWORD WINAPI RemoteThreadProc(LPVOID lpParam)
{

	char msgboxName[] = { 'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'A', '\0' };
	char kernelName[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', '\0' };
	char loadlibName[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };
	char loadDllName[] = { 'N', 'e', 't', 'h', 'a', 'c', 'k', '.', 'd', 'l', 'l', '\0' };

	char mainName[] = { 'm', 'a', 'i', 'n' , '\0' };

	LPLOADLIBRARYA loadLibraryA = NULL;
	MAIN m = NULL;

	GETPROCADDRESS getProcAddress = (GETPROCADDRESS)*(unsigned long*)lpParam;
	GETMODULEHANDLE getMoudleHandle = (GETMODULEHANDLE)*((unsigned char*)lpParam + 4);

	_asm{
		mov eax, lpParam
		mov ebx, [eax]
		mov getProcAddress, ebx

		add eax, 4
		mov ebx, [eax]
		mov getMoudleHandle, ebx
	}


	HMODULE kernel32module = getMoudleHandle(kernelName);

	loadLibraryA = (LPLOADLIBRARYA)getProcAddress(kernel32module, loadlibName);
	HMODULE nethackdll = loadLibraryA(loadDllName);
	if (nethackdll)
	{
		m = (MAIN)getProcAddress(getMoudleHandle(loadDllName), mainName);
		m();
	}
	return 0;
}
void afterFunc()
{
	return;
}
#pragma check_stack


int main(void)
{
	DWORD pid = 0;	//Red alert 3 PID;
	while (true)
	{
		pid = GetProcessIDByName(_T("ra3_1.12.game"));
		//pid = GetProcessIDByName(_T("RA3.exe"));
		if (pid != 0)
		{
			break;
		}
		Sleep(1000);
	}


	int* getProcAddress = (int*)GetProcAddress;
	int* getMoudleHandle = (int*)GetModuleHandleA;


	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	DWORD dwSize = ((BYTE *)(DWORD)afterFunc - (BYTE *)(DWORD)RemoteThreadProc);

	LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, dwSize + 8, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);	//申请1K地址

	if (WriteProcessMemory(hProcess, (unsigned char*)remoteMem + dwSize, (LPVOID)&getProcAddress, 4, NULL))
	{
		printf("写入GetProcAddress的地址完成\n");
	}
	else
	{
		printf("写入GetProcAddress的地址失败\n");
	}

	if (WriteProcessMemory(hProcess, (unsigned char*)remoteMem + dwSize + 4, (LPVOID)&getMoudleHandle, 4, NULL))
	{
		printf("写入GetModuleHandleA的地址完成\n");
	}
	else
	{
		printf("写入GetModuleHandleA的地址失败\n");
	}
	
	if (WriteProcessMemory(hProcess, remoteMem, RemoteThreadProc, dwSize, NULL) == TRUE)
	{
		printf("写入完成\n");
	}
	else
	{
		printf("写入失败\n");
	}
	CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)remoteMem, (unsigned char*)remoteMem + dwSize, NULL, NULL);




	/*
	TrueSocket = (_socket)GetProcAddress(GetModuleHandle(_T("ws2_32")), "socket");
	// Set the hook
	if (Mhook_SetHook((PVOID*)&TrueSocket, Hook_socket)) {
		socket(3, 3, 3);
		// Remove the hook
		Mhook_Unhook((PVOID*)&TrueSocket);
	}*/

	system("pause");
	return 0;
}
