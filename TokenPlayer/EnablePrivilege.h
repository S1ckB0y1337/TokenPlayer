#include <stdio.h>
#include <tchar.h>
#include <Windows.h>

//A function to enable SeDebugPrivilege if you have the proper rights
BOOL EnablePrivilege(LPCWSTR privilege) {
	//First lets get the LUID of the provided privilege
	LUID privLuid;
	if (!LookupPrivilegeValue(NULL, privilege, &privLuid)) {
		printf("LookupPrivilegeValue error() : % u\n", GetLastError());
		return false;
	}

	//Lets open a handle to our current process
	HANDLE hProcess = GetCurrentProcess();
	//Next open a handle to our token
	HANDLE hToken;
	//Use both TOKEN_QUERY and TOKEN_ADJUST_PRIVILEGES flags, so i can query the Token for information and also be able to adjust its privileges
	if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		printf("OpenProcessToken() error : % u\n", GetLastError());
		return false;
	}
	
	//Now lets prepare the structure for the privilege we try to enable
	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = privLuid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	//Finally enable the privilege on our current process
	if (!AdjustTokenPrivileges(hToken, false, &tp, NULL, NULL, NULL)) {
		printf("AdjustTokenPrivileges() error: %u\n", GetLastError());
		return false;
	}
	CloseHandle(hToken);
	CloseHandle(hProcess);
	return true;
}
