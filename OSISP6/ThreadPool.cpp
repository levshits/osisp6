#include "stdafx.h"
#include "ThreadPool.h"
#include "Task.h"
#include "Windows.h"
#include <time.h>
#pragma once
#include <iostream>
using namespace std;

ThreadPool::ThreadPool(int count)
{
	countOfThreads = count;
	threads = new HANDLE[count];
	isRunning = true;
	InitializeCriticalSection(&criticalSection);
	InitializeConditionVariable(&conditionVariable);
	InitializeConditionVariable(&conditionVariableTaskFinished);
	numberOfTasksNotFinished = 0;

	for (int i = 0; i<countOfThreads; i++)
	{
		threads[i] = CreateThread(nullptr, 0, ThreadStart, static_cast<void*>(this), 0, nullptr);
	}
}
DWORD WINAPI ThreadPool::ThreadStart(LPVOID threadParameters)
{
	ThreadPool* reference = static_cast<ThreadPool*>(threadParameters);
	printf("Thread is running with number %d\n", GetCurrentThreadId());
	return reference->ThreadMain();
}


void ThreadPool::Execute(Task* task)
{
	EnterCriticalSection(&criticalSection);
	tasks.push_back(task);
	numberOfTasksNotFinished++;
	LeaveCriticalSection(&criticalSection);
	WakeAllConditionVariable(&conditionVariable);
}


DWORD  ThreadPool::ThreadMain()
{
	do
	{
		Task* currentTask;
		EnterCriticalSection(&criticalSection);

		while (tasks.size() == 0 && isRunning)
			SleepConditionVariableCS(&conditionVariable, &criticalSection, INFINITE);

		if (!isRunning) 
		{
			LeaveCriticalSection(&criticalSection);
			return 0;
		}

		currentTask = tasks.front();
		tasks.pop_front();
		LeaveCriticalSection(&criticalSection);

		currentTask->Run();
		currentTask->Log();
		delete currentTask;
		EnterCriticalSection(&criticalSection);
		numberOfTasksNotFinished--;
		LeaveCriticalSection(&criticalSection);

		WakeAllConditionVariable(&conditionVariableTaskFinished);
	} while (isRunning);
	return 0;
}
ThreadPool::~ThreadPool()
{
	EnterCriticalSection(&criticalSection);
	while (numberOfTasksNotFinished != 0)
		SleepConditionVariableCS(&conditionVariableTaskFinished, &criticalSection, INFINITY);
	LeaveCriticalSection(&criticalSection);
	isRunning = false;
	WakeAllConditionVariable(&conditionVariable);
	for (int i = 0; i < countOfThreads; i++)
		WaitForSingleObject(threads[i], INFINITE);
	DeleteCriticalSection(&criticalSection);
}
