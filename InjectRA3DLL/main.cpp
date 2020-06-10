#include <WinSock2.h>

#include <tchar.h>
#include <mhook.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

typedef SOCKET(WSAAPI* _socket)(int af, int type, int protocol);
typedef int (WSAAPI* _connect)(SOCKET s, const struct sockaddr FAR* name, int namelen);
typedef struct hostent FAR *(WSAAPI* _gethostbyname)(const char* name);
typedef int (WSAAPI* _bind)(SOCKET s, _In_reads_bytes_(namelen) const struct sockaddr FAR * name, int namelen);


in_addr* myip;

_socket TrueSocket = NULL;
_connect TrueConnect = NULL;
_gethostbyname TrueGetHostByName = NULL;
_bind TrueBind = NULL;

SOCKET WSAAPI Hook_socket(int af, int type, int protocol)
{
	return TrueSocket(af, type, protocol);
}
int WSAAPI Hook_connect(SOCKET s, const struct sockaddr FAR* name, int namelen)
{
	return TrueConnect(s, name, namelen);
}
struct hostent FAR * WSAAPI HOOK_gethostbyname(const char* name)
{
	hostent* a = TrueGetHostByName(name);

	//((unsigned long**)(a->h_addr_list)) = (unsigned long)myip;
	memcpy(a->h_addr_list, &myip, 4);
	int b = 0;
	memcpy(a->h_addr_list + 1, &b, 4);
	return a;
}
int WSAAPI HOOK_bind(SOCKET s, _In_reads_bytes_(namelen) const struct sockaddr FAR * name, int namelen)
{
	return TrueBind(s, name, namelen);
}

extern "C"
{
	__declspec(dllexport) void main()
	{
		MessageBox(NULL, _T("已经注入红色警戒3"), _T("来自坚老哥的提示"), NULL);


		myip = new in_addr;// 0xc0a86405; //192.168.100.5
		myip->s_addr = 0x0264a8c0;
		
		TrueSocket = (_socket)GetProcAddress(GetModuleHandle(_T("ws2_32")), "socket");
		TrueConnect = (_connect)GetProcAddress(GetModuleHandle(_T("ws2_32")), "connect");
		TrueGetHostByName = (_gethostbyname)GetProcAddress(GetModuleHandle(_T("ws2_32")), "gethostbyname");
		TrueBind = (_bind)GetProcAddress(GetModuleHandle(_T("ws2_32")), "bind");
		// Set the hook
		Mhook_SetHook((PVOID*)&TrueSocket, Hook_socket);
		Mhook_SetHook((PVOID*)&TrueConnect, Hook_connect);
		Mhook_SetHook((PVOID*)&TrueGetHostByName, HOOK_gethostbyname);
		Mhook_SetHook((PVOID*)&TrueBind, HOOK_bind);
		
	}
}