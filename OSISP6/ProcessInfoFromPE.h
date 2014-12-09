#pragma once
#include "Task.h"
#include "Windows.h"
class ProcessInfoFromPE :
	public Task
{
public:
	ProcessInfoFromPE(DWORD Pid);
	virtual ~ProcessInfoFromPE();
	virtual void Run();
	virtual void Log();
private:
	DWORD _pid;
	TCHAR* filename = nullptr;
	FILE* file;
	LPBYTE OpenPEFile(LPCTSTR lpszFileName);
	void ClosePEFile(LPBYTE pBase);
	BOOL ListProcessModules(DWORD dwPID);
	void logData(TCHAR* path);
	void printError(TCHAR* msg);
	IMAGE_NT_HEADERS* GetHeader(LPBYTE pBase);
	IMAGE_SECTION_HEADER* GetSection(IMAGE_NT_HEADERS* pHeader, DWORD dwRVA);
	void GetImportTableData(LPBYTE pBase);
	LPBYTE GetFilePointer(LPBYTE pBase, DWORD dwRVA);
};

