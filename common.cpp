#include "common.h"
#include "status.h"
#include "WeChat/WeChat.h"

#include <stdio.h>
#include <time.h>

VOID GetDirectoryFromFilePath(const CHAR *filePath, CHAR *directoryPath)
{
	const CHAR *lastSlash = strrchr(filePath, '\\');

	if (lastSlash == NULL)
	{
		strcpy_s(directoryPath, MAX_PATH, "");
		return;
	}

	strncpy_s(directoryPath, MAX_PATH, filePath, lastSlash - filePath);
	directoryPath[lastSlash - filePath] = '\0';
}

BOOL CheckSQLiteDBHeader(const char *szDBFilePath)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	BYTE Data[256] = {0x00};

	hFile = CreateFileA(szDBFilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("CreateFileA open %s fail, error: %d\n", szDBFilePath, GetLastError());
		return FALSE;
	}

	memset(Data, 0x00, sizeof(Data));
	if (!ReadFile(hFile, Data, sizeof(Data), NULL, NULL))
	{
		CloseHandle(hFile);
		return FALSE;
	}

	CloseHandle(hFile);
	return TRUE;
}

BOOL FilterPos(BYTE *pos)
{
	int i = 0;

	for (int z = 0; z <= 0xFF; z++)
	{
		i = 0;

		for (int j = 0; j < 0x20; j++)
		{
			if (pos[j] == z)
			{
				i++;
			}

			if (i > 2)
			{
				return FALSE;
			}
		}
	}

	return TRUE;
}

DWORD WINAPI CrackingThread(LPVOID lpParam)
{
	CRACKING_ARGS *pCrackingArgs = (CRACKING_ARGS *)lpParam;
	int progressInterval = 1000;
	int counter = 0;
	SYSTEMTIME LocalTime;

	for (int Pos = 0; Pos < pCrackingArgs->MappingFileDataSize; Pos++)
	{
		if (!FilterPos((BYTE *)pCrackingArgs->pMappingFileData + Pos))
		{
			continue;
		}

		if (WaitForSingleObject(pCrackingArgs->hStopEvent, 0) == WAIT_OBJECT_0)
		{
			return 0;
		}

		if (pCrackingArgs->CheckingFunction((BYTE *)pCrackingArgs->pMappingFileData + Pos, pCrackingArgs->PasswordSize, (BYTE *)pCrackingArgs->PageData, pCrackingArgs->PageDataSize))
		{
			printf("Thread %d: Find password, pos: %llx\n", pCrackingArgs->ThreadId, Pos + (pCrackingArgs->ThreadId - 1) * pCrackingArgs->MappingFileDataSize);
			printf("password: ");
			for (int j = 0; j < pCrackingArgs->PasswordSize; j++)
			{
				printf("%02X ", *(BYTE *)((BYTE *)pCrackingArgs->pMappingFileData + Pos + j));
			}
			HANDLE hOutPut = CreateFileA(pCrackingArgs->szPasswordFilePath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			WriteFile(hOutPut, (BYTE *)pCrackingArgs->pMappingFileData + Pos, pCrackingArgs->PasswordSize, NULL, NULL);
			CloseHandle(hOutPut);
			SetEvent(pCrackingArgs->hStopEvent);
			return 1;
		}

		if (counter++ % progressInterval == 0)
		{
			GetLocalTime(&LocalTime);
			double progress = (double)Pos / pCrackingArgs->MappingFileDataSize * 100;
			printf("%02d:%02d:%02d.%03d---Thread %d: pos: %llx/%llx  Progress %.2f%%  Time Elapsed: %llu s\n", LocalTime.wHour, LocalTime.wMinute, LocalTime.wSecond, LocalTime.wMilliseconds, pCrackingArgs->ThreadId,
				   Pos + (pCrackingArgs->ThreadId - 1) * pCrackingArgs->MappingFileDataSize, pCrackingArgs->TotalMappingFileDataSize, progress,
				   (GetTickCount64() - pCrackingArgs->StartTime) / 1000);
			SaveCrackingStatus(pCrackingArgs, Pos);
		}
	}

	return 0;
}

BOOL CrackingDBFile(LPVOID pMappingFileData, LARGE_INTEGER FileSize, BYTE *PageData, CHAT_TYPE ChatType, const CHAR *szPasswordFilePath, int ThreadNum)
{
	CRACKING_ARGS *pCrackingArgs;
	HANDLE *hThreads;
	HANDLE hStopEvent;
	int AlignSize;
	DWORD dwThreadId;
	CHAR szTaskDir[MAX_PATH] = { 0x00 };

	AlignSize = FileSize.LowPart / ThreadNum;

	pCrackingArgs = (CRACKING_ARGS *)malloc(ThreadNum * sizeof(CRACKING_ARGS));
	memset(pCrackingArgs, 0x00, ThreadNum * sizeof(CRACKING_ARGS));
	hThreads = (HANDLE *)malloc(ThreadNum * sizeof(HANDLE));

	if (pCrackingArgs == NULL || hThreads == NULL)
	{
		printf("Memory allocation failed\n");
		return FALSE;
	}

	hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (hStopEvent == NULL)
	{
		printf("CreateEvent failed\n");
		free(pCrackingArgs);
		free(hThreads);
		return FALSE;
	}

	GetDirectoryFromFilePath(szPasswordFilePath, szTaskDir);
	for (int i = 0; i < ThreadNum; i++)
	{
		pCrackingArgs[i].pMappingFileData = (BYTE *)pMappingFileData + i * AlignSize;
		pCrackingArgs[i].MappingFileDataSize = AlignSize;
		pCrackingArgs[i].PageData = PageData;
		pCrackingArgs[i].hStopEvent = hStopEvent;
		pCrackingArgs[i].ThreadId = i + 1;
		pCrackingArgs[i].ThreadNum = ThreadNum;
		pCrackingArgs[i].StartTime = GetTickCount64();
		pCrackingArgs[i].TotalMappingFileDataSize = FileSize.QuadPart;
		memcpy(pCrackingArgs[i].szPasswordFilePath, szPasswordFilePath, strlen(szPasswordFilePath));
		memcpy(pCrackingArgs[i].szTaskDir, szTaskDir, strlen(szTaskDir));
		switch (ChatType)
		{
		case WECHAT:
			pCrackingArgs[i].CheckingFunction = CheckingWeChatMsgDBPassword;
			pCrackingArgs[i].PasswordSize = WECHAT_PASSWORD_SIZE;
			pCrackingArgs[i].PageDataSize = WECHAT_PAGE_SIZE;
			break;

		default:
			break;
		}

		hThreads[i] = CreateThread(NULL, 0, CrackingThread, &pCrackingArgs[i], 0, &dwThreadId);
		if (hThreads[i] == NULL)
		{
			printf("Thread creation failed\n");
			CloseHandle(hStopEvent);
			free(pCrackingArgs);
			free(hThreads);
			return FALSE;
		}
	}

	WaitForMultipleObjects(ThreadNum, hThreads, FALSE, INFINITE);
	for (int i = 0; i < ThreadNum; i++)
	{
		CloseHandle(hThreads[i]);
	}
	CloseHandle(hStopEvent);
	free(pCrackingArgs);
	free(hThreads);

	return TRUE;
}

VOID DeleteDirectory(const CHAR *Path)
{
	WIN32_FIND_DATAA FindFileData;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	CHAR DirPath[MAX_PATH];
	CHAR FilePath[MAX_PATH];

	sprintf_s(DirPath, "%s\\*", Path);
	hFind = FindFirstFileA(DirPath, &FindFileData);
	if (hFind == INVALID_HANDLE_VALUE)
	{
		return;
	}

	do
	{
		if (strcmp(FindFileData.cFileName, ".") != 0 && strcmp(FindFileData.cFileName, "..") != 0)
		{
			sprintf_s(FilePath, "%s\\%s", Path, FindFileData.cFileName);

			if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				DeleteDirectory(FilePath);
			}
			else
			{
				DeleteFileA(FilePath);
			}
		}
	} while (FindNextFileA(hFind, &FindFileData) != 0);

	FindClose(hFind);
	RemoveDirectoryA(Path);
}
