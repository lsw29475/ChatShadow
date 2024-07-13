#include "task.h"
#include "WeChat/WeChat.h"

#include <stdio.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

BOOL CreateNewCrackTask(CRACK_TASK* pTask)
{
	CHAR DestPathMem[MAX_PATH];
	CHAR DestPathDB[MAX_PATH];
	CHAR DecDBFilePath[MAX_PATH];
	CHAR PasswordFilePath[MAX_PATH];

	if (PathFileExistsA(pTask->szTaskDir))
	{
		DeleteDirectory(pTask->szTaskDir);
	}

	if (!CreateDirectoryA(pTask->szTaskDir, NULL))
	{
		printf("Failed to create directory: %s\n", pTask->szTaskDir);
		return FALSE;
	}

	sprintf_s(DestPathMem, "%s\\TaskMem.DMP", pTask->szTaskDir);
	if (!CopyFileA(pTask->szMemoryFilePath, DestPathMem, FALSE))
	{
		printf("Failed to copy file: %s\n", pTask->szMemoryFilePath);
		return FALSE;
	}

	sprintf_s(DestPathDB, "%s\\TaskDB.db", pTask->szTaskDir);
	if (!CopyFileA(pTask->szMsgDBFilePath, DestPathDB, FALSE))
	{
		printf("Failed to copy file: %s\n", pTask->szMsgDBFilePath);
		return FALSE;
	}

	sprintf_s(DecDBFilePath, "%s\\DecDB.db", pTask->szTaskDir);
	sprintf_s(PasswordFilePath, "%s\\Password", pTask->szTaskDir);
	switch (pTask->TaskType)
	{
	case WECHAT:
		CrackWeChatMsgDBFile(pTask->szMemoryFilePath, pTask->szMsgDBFilePath, DecDBFilePath, PasswordFilePath, pTask->ThreadNum);
		break;

	default:
		break;
	}

	return TRUE;
}