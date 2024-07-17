#pragma once
#include "common.h"

#include <Windows.h>

typedef struct _CRACK_TASK
{
	CHAT_TYPE TaskType;
    CHAR szMemoryFilePath[MAX_PATH];
    CHAR szMsgDBFilePath[MAX_PATH];
    CHAR szTaskDir[MAX_PATH];
    int ThreadNum;
} CRACK_TASK, *PCRACK_TASK;

BOOL CreateNewCrackTask(CRACK_TASK* pCrackTask);
BOOL ResumeCrackTask(const CHAR* szTaskDir);
