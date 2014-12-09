#include "Task.h"
#include "Windows.h"
#include <list>
#pragma once
class ThreadPool
{
public:
	ThreadPool(int count);
	virtual ~ThreadPool();
	void Execute(Task *task);
private:
	int countOfThreads;
	bool isRunning;
	HANDLE* threads;
	CRITICAL_SECTION criticalSection;
	CONDITION_VARIABLE conditionVariable;
	CONDITION_VARIABLE conditionVariableTaskFinished;
	int numberOfTasksNotFinished;
	static DWORD WINAPI ThreadStart(LPVOID threadParameters);
	DWORD  ThreadMain();
	std::list<Task*> tasks;

};
