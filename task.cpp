#include "task.h"
#include "status.h"
#include "WeChat/WeChat.h"

#include <stdio.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

BOOL CreateNewCrackTask(CRACK_TASK *pTask)
{
	CHAR DestPathMem[MAX_PATH] = {0x00};
	;
	CHAR DestPathDB[MAX_PATH] = {0x00};
	;
	CHAR DecDBFilePath[MAX_PATH] = {0x00};
	;
	CHAR PasswordFilePath[MAX_PATH] = {0x00};
	;

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
		CrackWeChatMsgDBFile(pTask->szMemoryFilePath, pTask->szMsgDBFilePath, DecDBFilePath, PasswordFilePath, pTask->ThreadNum, FALSE);
		break;

	default:
		break;
	}

	return TRUE;
}

BOOL ResumeCrackTask(const CHAR *szTaskDir)
{
	CRACK_TASK CrackTask;
	CHAR szStatusFilePath[MAX_PATH] = {0x00};
	CHAR DecDBFilePath[MAX_PATH] = {0x00};
	;
	CHAR PasswordFilePath[MAX_PATH] = {0x00};
	;

	if (!PathFileExistsA(szTaskDir))
	{
		printf("taskdir %s not exist\n", szTaskDir);
		return FALSE;
	}
	sprintf_s(szStatusFilePath, "%s\\Status.txt", szTaskDir);
	if (!PathFileExistsA(szStatusFilePath))
	{
		printf("status file %s not exist\n", szStatusFilePath);
		return FALSE;
	}

	memset(&CrackTask, 0x00, sizeof(CRACK_TASK));
	memcpy(CrackTask.szTaskDir, szTaskDir, strlen(szTaskDir));
	sprintf_s(CrackTask.szMemoryFilePath, "%s\\TaskMem.DMP", CrackTask.szTaskDir);
	sprintf_s(CrackTask.szMsgDBFilePath, "%s\\TaskDB.db", CrackTask.szTaskDir);
	sprintf_s(DecDBFilePath, "%s\\DecDB.db", CrackTask.szTaskDir);
	sprintf_s(PasswordFilePath, "%s\\Password", CrackTask.szTaskDir);

	switch (GetChatTypeFromStatusFile(szStatusFilePath))
	{
	case WECHAT:
		CrackWeChatMsgDBFile(CrackTask.szMemoryFilePath, CrackTask.szMsgDBFilePath, DecDBFilePath, PasswordFilePath, GetThreadNumFromStatusFile(szStatusFilePath), TRUE);
		break;
	
	default:
		break;
	}
}