#include "stdafx.h"
#include "ProcessInfoFromPE.h"
#include <ctime>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <delayimp.h>



ProcessInfoFromPE::ProcessInfoFromPE(DWORD Pid)
{
	_pid = Pid;
	filename = nullptr;
	file = nullptr;
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, _pid);
	filename = nullptr;
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		printf("Snapshot making error\n");
		return;
	}
	me32.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(hModuleSnap, &me32))
	{
		printError(TEXT("Module32First"));
		CloseHandle(hModuleSnap);
		return;
	}
	filename = (wchar_t*)malloc(sizeof(wchar_t)*wcslen(me32.szExePath));
	wcscpy(filename,me32.szExePath);
	wchar_t* resultFile = (wchar_t*)malloc(300*sizeof(wchar_t));
	wcscpy(resultFile, me32.szModule);
	wcscat(resultFile, L".txt\0");
	file = _wfopen(resultFile, L"wt+");
	free(resultFile);
	fprintf(file, "\n    MODULE NAME:     %ls", me32.szModule);
	fprintf(file, "\n     Executable     = %ls", me32.szExePath);
	
}


ProcessInfoFromPE::~ProcessInfoFromPE()
{
	if (file!=nullptr)
	fclose(file);
}

void ProcessInfoFromPE::Run()
{
	
	logData(filename);
}

void ProcessInfoFromPE::Log()
{
	printf("%d ready\n", _pid);
}

LPBYTE ProcessInfoFromPE::OpenPEFile(LPCTSTR lpszFileName)
{
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

void ProcessInfoFromPE::ClosePEFile(LPBYTE pBase)
{
	if (pBase != NULL)
		UnmapViewOfFile(pBase);
}

BOOL ProcessInfoFromPE::ListProcessModules(DWORD dwPID)
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

void ProcessInfoFromPE::logData(TCHAR* path)
{
	if (path == NULL)
	{

		printf("Read error\n");
		return;
	}
	LPBYTE filePointer = OpenPEFile(path);
	

	IMAGE_NT_HEADERS* pHeader = GetHeader(filePointer);
	if (pHeader == NULL) {
		fprintf(file, "\nIt is not a PE file!\n");
		return;
	}
	IMAGE_SECTION_HEADER* pSectHeader = IMAGE_FIRST_SECTION(pHeader);
	fprintf(file, "\nSections\n");
	for (size_t i = 0; i < pHeader->FileHeader.NumberOfSections; i++, pSectHeader++)
	{
		BYTE* Name = pSectHeader->Name;
		DWORD VirtualAddress = pSectHeader->VirtualAddress;
		DWORD SizeOfRawData = pSectHeader->SizeOfRawData;
		fprintf(file, "address %d size %d\n", VirtualAddress, SizeOfRawData);

	}
	DWORD AddressOfEntryPoint = pHeader->OptionalHeader.AddressOfEntryPoint;
	fprintf(file, "\nAddressOfEntryPoint %d\n", AddressOfEntryPoint);
	GetImportTableData(filePointer);
	ClosePEFile(filePointer);
}

void ProcessInfoFromPE::printError(TCHAR* msg)
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

IMAGE_NT_HEADERS* ProcessInfoFromPE::GetHeader(LPBYTE pBase)
{
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

IMAGE_SECTION_HEADER* ProcessInfoFromPE::GetSection(IMAGE_NT_HEADERS* pHeader, DWORD dwRVA)
{
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

void ProcessInfoFromPE::GetImportTableData(LPBYTE pBase)
{
	using namespace std;
	IMAGE_NT_HEADERS* pHeader = GetHeader(pBase);
	if (pHeader == NULL) {
		fprintf(file, "It is not a PE file!\n");
		return;
	}
	IMAGE_DATA_DIRECTORY& ImportDataDir = pHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (ImportDataDir.Size != 0) {
		fprintf(file, "Import Data Directory\n\n");
		for (IMAGE_IMPORT_DESCRIPTOR* pImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)GetFilePointer(pBase, ImportDataDir.VirtualAddress);
			pImportDesc->Name != 0; pImportDesc++) {
			char* name = strupr(strdup((char*)GetFilePointer(pBase, pImportDesc->Name)));
			fprintf(file, "%s\n", name);
			free(name);
			time_t time = pImportDesc->TimeDateStamp;
			bool bBounded = false, bOldBind = false;
			if (time == 0)
				fprintf(file, "DLL not bounded\n");
			else if (time == -1) {
				fprintf(file, "New style bounding, see Bound Import Data Directory below\n");
				bBounded = true;
			}
			else {
				fprintf(file, "Old style bounding. Date/Time: %s" , asctime(gmtime(&time)));
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
					fprintf(file, "\nAddress\t\tHint\tName/Ordinal\tForwarded\n");
				else
					fprintf(file, "\nAddress\t\tHint\tName/Ordinal\n" );
			}
			else
				fprintf(file, "\nHint\tName/Ordinal\n");
			for (DWORD i = 0; pINT->u1.Ordinal != 0; i++) {
				if (bBounded)
					fprintf(file,"0x%X\t", (DWORD)(ULONG_PTR)GetFilePointer(pBase, pIAT->u1.Ordinal));
				if (IMAGE_SNAP_BY_ORDINAL(pINT->u1.Ordinal))
					fprintf(file, "\t %d", (pINT->u1.Ordinal & ~IMAGE_ORDINAL_FLAG));
				else {
					IMAGE_IMPORT_BY_NAME* p = (IMAGE_IMPORT_BY_NAME*)GetFilePointer(pBase, pINT->u1.Ordinal);
			
					fprintf(file, " %d \t %s", p->Hint, (char*)p->Name);
				}
				/*if (bOldBind)
					cout << (find(forwardRefs.begin(), forwardRefs.end(), i) == forwardRefs.end() ? "\tN" : "\tY");*/
				fprintf(file, "\n");
				pINT++; pIAT++;
			}
			fprintf(file, "\n");
		}
	}
	// Извлекаем параметры каталога данных связывания импорта.
	IMAGE_DATA_DIRECTORY& BoundImportDataDir = pHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
	if (BoundImportDataDir.Size != 0) {
		fprintf(file, "Bound Import Data Directory\n");
		fprintf(file, "---------------------------\n\n");
		LPBYTE pBoundImportDir = GetFilePointer(pBase, BoundImportDataDir.VirtualAddress);
		for (IMAGE_BOUND_IMPORT_DESCRIPTOR* pBoundImportDesc = (IMAGE_BOUND_IMPORT_DESCRIPTOR*)pBoundImportDir;
			pBoundImportDesc->OffsetModuleName != 0;) {
			char* name = strupr(strdup((char*)(pBoundImportDir + pBoundImportDesc->OffsetModuleName)));
			fprintf(file, "%s\n", name);
			free(name);
			time_t time = pBoundImportDesc->TimeDateStamp;
			fprintf(file, "Date/Time: %s", asctime(gmtime(&time)));
			if (pBoundImportDesc->NumberOfModuleForwarderRefs == 0) {
				fprintf(file, "No forwarder refs");
				pBoundImportDesc++;
			}
			else {
				fprintf(file, "Forwarder refs:");
				fprintf(file, "\nName\t\tDate/Time\n");
				IMAGE_BOUND_FORWARDER_REF* pForwardRef = (IMAGE_BOUND_FORWARDER_REF*)(pBoundImportDesc + 1);
				for (UINT i = 0; i < pBoundImportDesc->NumberOfModuleForwarderRefs; i++, pForwardRef++) {
					char* name = strupr(strdup((char*)(pBoundImportDir + pForwardRef->OffsetModuleName)));
					time_t time = pForwardRef->TimeDateStamp;
					fprintf(file, "%s \t %s", name, asctime(gmtime(&time)));
					free(name);
				}
				pBoundImportDesc = (IMAGE_BOUND_IMPORT_DESCRIPTOR*)pForwardRef;
			}
			fprintf(file, "\n");
		}
	}
	// Извлекаем параметры каталога данных отложенного импорта.
	IMAGE_DATA_DIRECTORY& DelayImportDataDir = pHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
	if (DelayImportDataDir.Size != 0) {
		fprintf(file, "Delay Import Data Directory\n\n");
		for (ImgDelayDescr* pDelayDesc = (ImgDelayDescr*)GetFilePointer(pBase, DelayImportDataDir.VirtualAddress);
			pDelayDesc->rvaDLLName != 0; pDelayDesc++) {
			if (pDelayDesc->grAttrs & dlattrRva) {
				char* name = strupr(strdup((char*)GetFilePointer(pBase, pDelayDesc->rvaDLLName)));
				fprintf(file, "%s\n", name);
				free(name);
				fprintf(file, "Attributes:\tVisual Studio .NET\n");
				fprintf(file, "HMODULE:\t 0x%X\n", *(LPDWORD)GetFilePointer(pBase, pDelayDesc->rvaHmod));
				time_t time = pDelayDesc->dwTimeStamp;
				if (time != 0)
					fprintf(file, "Date/Time:\t %s", asctime(gmtime(&time)));
				else
					fprintf(file, "Date/Time:\tnot set\n");
				fprintf(file, "\nAddress\t\tHint\tName/Ordinal\n");
				IMAGE_THUNK_DATA* pINT = (IMAGE_THUNK_DATA*)GetFilePointer(pBase, pDelayDesc->rvaINT);
				IMAGE_THUNK_DATA* pIAT = (IMAGE_THUNK_DATA*)GetFilePointer(pBase, pDelayDesc->rvaIAT);
				while (pINT->u1.Ordinal != 0) {
					fprintf(file, "0x%X\t",(DWORD)(ULONG_PTR)GetFilePointer(pBase, pIAT->u1.Ordinal));
					if (IMAGE_SNAP_BY_ORDINAL(pINT->u1.Ordinal))
						fprintf(file, "\t %d \n", (pINT->u1.Ordinal & ~IMAGE_ORDINAL_FLAG));
					else {
						IMAGE_IMPORT_BY_NAME* p = (IMAGE_IMPORT_BY_NAME*)GetFilePointer(pBase, pINT->u1.Ordinal);
						fprintf(file, " %d \t %s", p->Hint, (char*)p->Name);

					}
					pINT++; pIAT++;
				}
			}
		}
	}
	ClosePEFile(pBase);
}

LPBYTE ProcessInfoFromPE::GetFilePointer(LPBYTE pBase, DWORD dwRVA)
{
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