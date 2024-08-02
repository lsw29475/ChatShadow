#include "common.h"
#include "status.h"
#include "WeChat/WeChat.h"
#include "QQ/QQ.h"

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

DWORD WINAPI CrackingThread(LPVOID lpParam)
{
	CRACKING_ARGS *pCrackingArgs = (CRACKING_ARGS *)lpParam;
	int counter = 0;
	SYSTEMTIME LocalTime;
	int Pos = 0;

	int CurUsedTime = 0;
	int OldUsedTime = 0;
	int NewUsedTime = 0;

	if (pCrackingArgs->blResume)
	{
		CHAR szStatusFilePath[MAX_PATH] = {0x00};
		sprintf_s(szStatusFilePath, "%s\\Status.txt", pCrackingArgs->szTaskDir);
		Pos = GetLastPosFromStatusFile(szStatusFilePath, pCrackingArgs->ThreadId);
		OldUsedTime = GetUsedTimeFromStatusFile(szStatusFilePath, pCrackingArgs->ThreadId);
	}

	for (; Pos < pCrackingArgs->MappingFileDataSize; Pos++)
	{
		if (!pCrackingArgs->FilterPosFunction((BYTE *)pCrackingArgs->pMappingFileData + Pos))
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
			pCrackingArgs->PrintAndSavePasswordFunction((BYTE *)pCrackingArgs->pMappingFileData + Pos, pCrackingArgs->szPasswordFilePath);
			SetEvent(pCrackingArgs->hStopEvent);
			return 1;
		}

		if (counter++ % pCrackingArgs->ProgressInterval == 0)
		{
			GetLocalTime(&LocalTime);
			double progress = (double)Pos / pCrackingArgs->MappingFileDataSize * 100;
			CurUsedTime = (GetTickCount64() - pCrackingArgs->StartTime) / 1000;
			NewUsedTime = OldUsedTime + CurUsedTime;
			printf("%02d:%02d:%02d.%03d---Thread %d: pos: %llx/%llx  Progress %.2f%%  Time Elapsed: %llu s  Totally Used: %llu s\n", LocalTime.wHour, LocalTime.wMinute, LocalTime.wSecond, LocalTime.wMilliseconds, pCrackingArgs->ThreadId,
				   Pos + (pCrackingArgs->ThreadId - 1) * pCrackingArgs->MappingFileDataSize, pCrackingArgs->TotalMappingFileDataSize, progress,
				   CurUsedTime, NewUsedTime);
			SaveCrackingStatus(pCrackingArgs, Pos, NewUsedTime);
		}
	}

	return 0;
}

BOOL CrackingDBFile(LPVOID pMappingFileData, LARGE_INTEGER FileSize, BYTE *PageData, CHAT_TYPE ChatType, const CHAR *szPasswordFilePath, int ThreadNum, BOOL blResume)
{
	CRACKING_ARGS *pCrackingArgs;
	HANDLE *hThreads;
	HANDLE hStopEvent;
	int AlignSize;
	DWORD dwThreadId;
	CHAR szTaskDir[MAX_PATH] = {0x00};

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
		pCrackingArgs[i].ChatType = ChatType;
		pCrackingArgs[i].blResume = blResume;
		memcpy(pCrackingArgs[i].szPasswordFilePath, szPasswordFilePath, strlen(szPasswordFilePath));
		memcpy(pCrackingArgs[i].szTaskDir, szTaskDir, strlen(szTaskDir));
		switch (ChatType)
		{
		case WECHAT:
			pCrackingArgs[i].CheckingFunction = CheckingWeChatMsgDBPassword;
			pCrackingArgs[i].FilterPosFunction = FilterWeChatPos;
			pCrackingArgs[i].PrintAndSavePasswordFunction = PrintAndSaveWeChatMsgDBPassword;
			pCrackingArgs[i].PasswordSize = WECHAT_CHECK_PASSWORD_SIZE;
			pCrackingArgs[i].PageDataSize = WECHAT_PAGE_SIZE;
			pCrackingArgs[i].ProgressInterval = WECHAT_PROGRESS_INTERVAL;
			break;

		case QQ:
			pCrackingArgs[i].CheckingFunction = CheckingQQMsgDBPassword;
			pCrackingArgs[i].FilterPosFunction = FilterQQPos;
			pCrackingArgs[i].PrintAndSavePasswordFunction = PrintAndSaveQQMsgDBPassword;
			pCrackingArgs[i].PasswordSize = QQ_CHECK_PASSWORD_SIZE;
			pCrackingArgs[i].PageDataSize = QQ_PAGE_SIZE;
			pCrackingArgs[i].ProgressInterval = QQ_PROGRESS_INTERVAL;
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

	WaitForMultipleObjects(ThreadNum, hThreads, TRUE, INFINITE);
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
