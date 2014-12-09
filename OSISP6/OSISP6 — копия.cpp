// OSISP6.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <ctime>
#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <delayimp.h>
#include "ThreadPool.h"


//  Forward declarations:
BOOL GetProcessList();
BOOL ListProcessModules(DWORD dwPID);
BOOL ListProcessThreads(DWORD dwOwnerPID);
void logData(TCHAR* path);
void printError(TCHAR* msg);
IMAGE_NT_HEADERS* GetHeader(LPBYTE pBase);
void GetImportTableData(LPBYTE pBase);
LPBYTE GetFilePointer(LPBYTE pBase, DWORD dwRVA);

const int _threadPoolSize = 8;
ThreadPool* pool;
SOCKET serverSocket;

BOOL CtrlHandler(DWORD fdwCtrlType)
{
	switch (fdwCtrlType)
	{
	default:
	{
			   printf("Stoping\n");
			   delete pool;
			   closesocket(serverSocket);
			   WSACleanup();
			   return FALSE;
	}

	}
}

int _tmain(int argc, _TCHAR* argv[])
{
	setlocale(LC_ALL, "Russian");
	system("chcp 1251");
	system("cls");
	pool = new ThreadPool(_threadPoolSize);
	if (SetConsoleCtrlHandler(PHANDLER_ROUTINE(CtrlHandler), TRUE))
	{
		GetProcessList();
		while (1)
		{
			printf("Please enter PID of process\n");
			DWORD Pid;
			scanf("%d", &Pid);
					
		}
			
	}

	else
	{
		printf("\nERROR: Could not set control handler");
		return 1;
	}
	return 0;
}

IMAGE_SECTION_HEADER* GetSection(IMAGE_NT_HEADERS* pHeader, DWORD dwRVA) {
	// Проверка правильности аргументов.
	if (pHeader == NULL)
		return NULL;
	// Перебор всех заголовков секций.
	IMAGE_SECTION_HEADER* pSectHeader = IMAGE_FIRST_SECTION(pHeader);
	for (UINT i = 0; i < pHeader->FileHeader.NumberOfSections; i++, pSectHeader++) {
		// Если RVA находится внутри секции, то возвращаем указатель на ее заголовок.
		if (dwRVA >= pSectHeader->VirtualAddress && dwRVA < pSectHeader->VirtualAddress + pSectHeader->Misc.VirtualSize)
			return pSectHeader;
	}
	return NULL; // секция не найдена
}
LPBYTE GetFilePointer(LPBYTE pBase, DWORD dwRVA) {
	// Проверка правильности аргументов.
	if (pBase == NULL)
		return NULL;
	// Ищем секцию, содержащий данный RVA.
	IMAGE_SECTION_HEADER* pSectHeader = GetSection(GetHeader(pBase), dwRVA);
	if (pSectHeader == NULL) // Если секция не найдена,
		return pBase + dwRVA; // то RVA равно смещению в файле,
	// иначе вычисляем смещение относительно начала секции в файле.
	return pBase + pSectHeader->PointerToRawData + (dwRVA - pSectHeader->VirtualAddress);
}
BOOL GetProcessList()
{
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD dwPriorityClass;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		printError(TEXT("CreateToolhelp32Snapshot (of processes)"));
		return(FALSE);
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32))
	{
		printError(TEXT("Process32First")); 
		CloseHandle(hProcessSnap);          
		return(FALSE);
	}

	do
	{
		_tprintf(TEXT("\n\n====================================================="));
		_tprintf(TEXT("\nPROCESS NAME:  %s"), pe32.szExeFile);
		_tprintf(TEXT("\n-------------------------------------------------------"));
		_tprintf(TEXT("\n  Process ID        = 0x%08X"), pe32.th32ProcessID);

		HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
		MODULEENTRY32 me32;
		hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
		if (hModuleSnap == INVALID_HANDLE_VALUE)
		{
			printError(TEXT("CreateToolhelp32Snapshot (of modules)"));
			continue;
		}
		me32.dwSize = sizeof(MODULEENTRY32);
		if (!Module32First(hModuleSnap, &me32))
		{
			printError(TEXT("Module32First"));  
			CloseHandle(hModuleSnap);           
			continue;
		}

			_tprintf(TEXT("\n    MODULE NAME:     %s"), me32.szModule);
			_tprintf(TEXT("\n     Executable     = %s"), me32.szExePath);
			logData(me32.szExePath);
			CloseHandle(hModuleSnap);

	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return(TRUE);
}
BOOL ListProcessModules(DWORD dwPID)
{
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		printError(TEXT("CreateToolhelp32Snapshot (of modules)"));
		return(FALSE);
	}

	me32.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(hModuleSnap, &me32))
	{
		printError(TEXT("Module32First"));  
		CloseHandle(hModuleSnap); 
		return(FALSE);
	}

	do
	{
		_tprintf(TEXT("\n\n     MODULE NAME:     %s"), me32.szModule);
		_tprintf(TEXT("\n     Executable     = %s"), me32.szExePath);
		_tprintf(TEXT("\n     Process ID     = 0x%08X"), me32.th32ProcessID);

	} while (Module32Next(hModuleSnap, &me32));

	CloseHandle(hModuleSnap);
	return(TRUE);
}
void printError(TCHAR* msg)
{
	DWORD eNum;
	TCHAR sysMsg[256];
	TCHAR* p;

	eNum = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, eNum,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		sysMsg, 256, NULL);
	p = sysMsg;
	while ((*p > 31) || (*p == 9))
		++p;
	do { *p-- = 0; } while ((p >= sysMsg) &&
		((*p == '.') || (*p < 33)));
	_tprintf(TEXT("\n  WARNING: %s failed with error %d (%s)"), msg, eNum, sysMsg);
}
LPBYTE OpenPEFile(LPCTSTR lpszFileName) {
	HANDLE hFile = CreateFile(lpszFileName, GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
		return NULL;
	HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	CloseHandle(hFile);
	LPBYTE pBase = NULL;
	if (hMapping != NULL) {
		pBase = (LPBYTE)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
		CloseHandle(hMapping);
	}
	return pBase;
}
IMAGE_NT_HEADERS* GetHeader(LPBYTE pBase) {
	if (pBase == NULL)
		return NULL;
	IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pBase;
	if (IsBadReadPtr(pDosHeader, sizeof(IMAGE_DOS_HEADER)))
		return NULL;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;
	IMAGE_NT_HEADERS* pHeader = (IMAGE_NT_HEADERS*)(pBase + pDosHeader->e_lfanew);
	if (IsBadReadPtr(pHeader, sizeof(IMAGE_NT_HEADERS)))
		return NULL;
	if (pHeader->Signature != IMAGE_NT_SIGNATURE)
		return NULL;
	return pHeader;
}
void ClosePEFile(LPBYTE pBase) {
	if (pBase != NULL)
		UnmapViewOfFile(pBase);
}
using namespace std;
void GetImportTableData(LPBYTE pBase)
{
	IMAGE_NT_HEADERS* pHeader = GetHeader(pBase);
	if (pHeader == NULL) {
		cout << "It is not a PE file!" << endl;
		return;
	}
	IMAGE_DATA_DIRECTORY& ImportDataDir = pHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (ImportDataDir.Size != 0) {
		cout << "Import Data Directory" << endl;
		cout << "---------------------" << endl << endl;
		for (IMAGE_IMPORT_DESCRIPTOR* pImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)GetFilePointer(pBase, ImportDataDir.VirtualAddress);
			pImportDesc->Name != 0; pImportDesc++) {
			char* name = strupr(strdup((char*)GetFilePointer(pBase, pImportDesc->Name)));
			cout << name << endl;
			free(name);
			time_t time = pImportDesc->TimeDateStamp;
			bool bBounded = false, bOldBind = false;
			if (time == 0)
				cout << "DLL not bounded" << endl;
			else if (time == -1) {
				cout << "New style bounding, see Bound Import Data Directory below" << endl;
				bBounded = true;
			}
			else {
				cout << "Old style bounding. Date/Time: " << asctime(gmtime(&time));
				bBounded = bOldBind = true;
			}
			IMAGE_THUNK_DATA* pINT;
			IMAGE_THUNK_DATA* pIAT;
			if (pImportDesc->OriginalFirstThunk != 0) {
				pINT = (IMAGE_THUNK_DATA*)GetFilePointer(pBase, pImportDesc->OriginalFirstThunk);
				pIAT = (IMAGE_THUNK_DATA*)GetFilePointer(pBase, pImportDesc->FirstThunk);
			}
			else { // учитываем ошибку сборщика TLINK
				pINT = (IMAGE_THUNK_DATA*)GetFilePointer(pBase, pImportDesc->FirstThunk);
				pIAT = NULL;
				bBounded = false;
			}
			std::vector<DWORD> forwardRefs;
			if (pImportDesc->ForwarderChain != -1 && bOldBind) {
				for (DWORD dwChain = pImportDesc->ForwarderChain; dwChain != -1; dwChain = pIAT[dwChain].u1.Ordinal)
					forwardRefs.push_back(dwChain);
			}
			if (bBounded) {
				if (bOldBind)
					cout << "\nAddress\t\tHint\tName/Ordinal\tForwarded" << endl;
				else
					cout << "\nAddress\t\tHint\tName/Ordinal" << endl;
			}
			else
				cout << "\nHint\tName/Ordinal" << endl;
			for (DWORD i = 0; pINT->u1.Ordinal != 0; i++) {
				if (bBounded)
					cout << hex << (DWORD)(ULONG_PTR)GetFilePointer(pBase, pIAT->u1.Ordinal) << '\t';
				if (IMAGE_SNAP_BY_ORDINAL(pINT->u1.Ordinal))
					cout << '\t' << dec << (pINT->u1.Ordinal & ~IMAGE_ORDINAL_FLAG);
				else {
					IMAGE_IMPORT_BY_NAME* p = (IMAGE_IMPORT_BY_NAME*)GetFilePointer(pBase, pINT->u1.Ordinal);
					cout << dec << p->Hint << '\t' << (char*)p->Name;
				}
				if (bOldBind)
					cout << (find(forwardRefs.begin(), forwardRefs.end(), i) == forwardRefs.end() ? "\tN" : "\tY");
				cout << endl;
				pINT++; pIAT++;
			}
			cout << endl;
		}
	}
	// Извлекаем параметры каталога данных связывания импорта.
	IMAGE_DATA_DIRECTORY& BoundImportDataDir = pHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
	if (BoundImportDataDir.Size != 0) {
		cout << "Bound Import Data Directory" << endl;
		cout << "---------------------------" << endl << endl;
		LPBYTE pBoundImportDir = GetFilePointer(pBase, BoundImportDataDir.VirtualAddress);
		for (IMAGE_BOUND_IMPORT_DESCRIPTOR* pBoundImportDesc = (IMAGE_BOUND_IMPORT_DESCRIPTOR*)pBoundImportDir;
			pBoundImportDesc->OffsetModuleName != 0;) {
			char* name = strupr(strdup((char*)(pBoundImportDir + pBoundImportDesc->OffsetModuleName)));
			cout << name << endl;
			free(name);
			time_t time = pBoundImportDesc->TimeDateStamp;
			cout << "Date/Time: " << asctime(gmtime(&time));
			if (pBoundImportDesc->NumberOfModuleForwarderRefs == 0) {
				cout << "No forwarder refs" << endl;
				pBoundImportDesc++;
			}
			else {
				cout << "Forwarder refs:" << endl;
				cout << "\nName\t\tDate/Time" << endl;
				IMAGE_BOUND_FORWARDER_REF* pForwardRef = (IMAGE_BOUND_FORWARDER_REF*)(pBoundImportDesc + 1);
				for (UINT i = 0; i < pBoundImportDesc->NumberOfModuleForwarderRefs; i++, pForwardRef++) {
					char* name = strupr(strdup((char*)(pBoundImportDir + pForwardRef->OffsetModuleName)));
					time_t time = pForwardRef->TimeDateStamp;
					cout << name << '\t' << asctime(gmtime(&time));
					free(name);
				}
				pBoundImportDesc = (IMAGE_BOUND_IMPORT_DESCRIPTOR*)pForwardRef;
			}
			cout << endl;
		}
	}
	// Извлекаем параметры каталога данных отложенного импорта.
	IMAGE_DATA_DIRECTORY& DelayImportDataDir = pHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
	if (DelayImportDataDir.Size != 0) {
		cout << "Delay Import Data Directory" << endl;
		cout << "---------------------------" << endl << endl;
		for (ImgDelayDescr* pDelayDesc = (ImgDelayDescr*)GetFilePointer(pBase, DelayImportDataDir.VirtualAddress);
			pDelayDesc->rvaDLLName != 0; pDelayDesc++) {
			if (pDelayDesc->grAttrs & dlattrRva) {
				char* name = strupr(strdup((char*)GetFilePointer(pBase, pDelayDesc->rvaDLLName)));
				cout << name << endl;
				free(name);
				cout << "Attributes:\tVisual Studio .NET" << endl;
				cout << "HMODULE:\t" << hex << *(LPDWORD)GetFilePointer(pBase, pDelayDesc->rvaHmod) << endl;
				time_t time = pDelayDesc->dwTimeStamp;
				if (time != 0)
					cout << "Date/Time:\t" << asctime(gmtime(&time));
				else
					cout << "Date/Time:\tnot set" << endl;
				cout << "\nAddress\t\tHint\tName/Ordinal" << endl;
				IMAGE_THUNK_DATA* pINT = (IMAGE_THUNK_DATA*)GetFilePointer(pBase, pDelayDesc->rvaINT);
				IMAGE_THUNK_DATA* pIAT = (IMAGE_THUNK_DATA*)GetFilePointer(pBase, pDelayDesc->rvaIAT);
				while (pINT->u1.Ordinal != 0) {
					cout << hex << (DWORD)(ULONG_PTR)GetFilePointer(pBase, pIAT->u1.Ordinal) << '\t';
					if (IMAGE_SNAP_BY_ORDINAL(pINT->u1.Ordinal))
						cout << '\t' << dec << (pINT->u1.Ordinal & ~IMAGE_ORDINAL_FLAG) << endl;
					else {
						IMAGE_IMPORT_BY_NAME* p = (IMAGE_IMPORT_BY_NAME*)GetFilePointer(pBase, pINT->u1.Ordinal);
						cout << dec << p->Hint << '\t' << (char*)p->Name << endl;
					}
					pINT++; pIAT++;
				}
			}
			else { // Не тестировано!!!
				char* name = strupr(strdup((char*)GetFilePointer(pBase, pDelayDesc->rvaDLLName - pHeader->OptionalHeader.ImageBase)));
				cout << name << endl;
				free(name);
				cout << "Attributes:\tVisual Studio 6.0" << endl;
				cout << "HMODULE:\t" << hex << *(LPDWORD)GetFilePointer(pBase, pDelayDesc->rvaHmod - pHeader->OptionalHeader.ImageBase) << endl;
				time_t time = pDelayDesc->dwTimeStamp;
				if (time != 0)
					cout << "Date/Time:\t" << asctime(gmtime(&time));
				else
					cout << "Date/Time:\tnot set" << endl;
				cout << "\nAddress\t\tHint\tName/Ordinal" << endl;
				IMAGE_THUNK_DATA* pINT = (IMAGE_THUNK_DATA*)GetFilePointer(pBase, pDelayDesc->rvaINT - pHeader->OptionalHeader.ImageBase);
				IMAGE_THUNK_DATA* pIAT = (IMAGE_THUNK_DATA*)GetFilePointer(pBase, pDelayDesc->rvaIAT - pHeader->OptionalHeader.ImageBase);
				while (pINT->u1.Ordinal != 0) {
					cout << hex << (DWORD)(ULONG_PTR)GetFilePointer(pBase, pIAT->u1.Ordinal) << '\t';
					if (IMAGE_SNAP_BY_ORDINAL(pINT->u1.Ordinal))
						cout << '\t' << dec << (pINT->u1.Ordinal & ~IMAGE_ORDINAL_FLAG) << endl;
					else {
						IMAGE_IMPORT_BY_NAME* p = (IMAGE_IMPORT_BY_NAME*)GetFilePointer(pBase, pINT->u1.Ordinal);
						cout << dec << p->Hint << '\t' << (char*)p->Name << endl;
					}
					pINT++; pIAT++;
				}
			}
			cout << endl;
		}
	}
	ClosePEFile(pBase);
}
void logData(TCHAR* path)
{
	LPBYTE filePointer = OpenPEFile(path);
	IMAGE_NT_HEADERS* pHeader = GetHeader(filePointer);
	if (pHeader == NULL) {
		std::cout << "It is not a PE file!" << std::endl;
		return;
	}
	IMAGE_SECTION_HEADER* pSectHeader = IMAGE_FIRST_SECTION(pHeader);
	_tprintf(TEXT("Sections"));
	for (size_t i = 0; i < pHeader->FileHeader.NumberOfSections; i++, pSectHeader++)
	{
		BYTE* Name = pSectHeader->Name;
		DWORD VirtualAddress = pSectHeader->VirtualAddress;
		DWORD SizeOfRawData = pSectHeader->SizeOfRawData;
		_tprintf(TEXT("address %d size %d\n"), VirtualAddress, SizeOfRawData);

	}
	DWORD AddressOfEntryPoint = pHeader->OptionalHeader.AddressOfEntryPoint;
	_tprintf(TEXT("AddressOfEntryPoint %d\n"), AddressOfEntryPoint);
	GetImportTableData(filePointer);	
	ClosePEFile(filePointer);
}
