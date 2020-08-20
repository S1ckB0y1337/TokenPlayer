#include <stdio.h>
#include <tchar.h>
#include <Windows.h>

//A function to enable SeDebugPrivilege if you have the proper rights
BOOL EnableDebugPrivilege(void) {
	//First lets get the LUID of the SeDebugPrivilege
	LUID debugLuid;
	if (!LookupPrivilegeValue(NULL, _T("SeDebugPrivilege"), &debugLuid)) {
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
	//Next we need to check if the token of the current process has the SeDebugPrivilege
	//First we will run GetTokenInformation with only the length parameter set, to get the length of the TokenInformation Structure
	DWORD structureSize, structureSize2;
	GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &structureSize);

	//Now lets execute again the same function using the structure size we got
	PTOKEN_PRIVILEGES tokenPrivs;
	//Allocate the structure by providing the calculated length of the structure
	tokenPrivs = (PTOKEN_PRIVILEGES)malloc(structureSize);
	if (!GetTokenInformation(hToken, TokenPrivileges, tokenPrivs, structureSize, &structureSize2)) {
		printf("GetTokenInformation() error : % u\n", GetLastError());
		return false;
	}

	//Finally lets check if the privilege exists in the Token information
	BOOL hasDebugPrivilege = false;
	PLUID_AND_ATTRIBUTES privilege;

	//Now iterate through all privileges and compare the LUIDs of each of them to the SeDebugPrivilege LUID
	for (DWORD i = 0; i < tokenPrivs->PrivilegeCount; i++) {
		privilege = &tokenPrivs->Privileges[i];
		//If we get a match we set the variable "hasDebugPrivilege" to true and break from the loop
		if (debugLuid.HighPart == privilege->Luid.HighPart && debugLuid.LowPart == privilege->Luid.LowPart) {
			hasDebugPrivilege = true;
			break;
		}
	}

	if (!hasDebugPrivilege) {
		return false;
	}
	//Now lets prepare the structure for the privilege we try to enable
	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = debugLuid;
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

