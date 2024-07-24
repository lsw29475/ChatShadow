#pragma once

#include "common.h"

VOID SaveCrackingStatus(CRACKING_ARGS *pCrackingArgs, int Pos, int UsedSeconds);
CHAT_TYPE GetChatTypeFromStatusFile(const CHAR* szStatusFilePath);
int GetLastPosFromStatusFile(const CHAR* szStatusFilePath, int ThreadId);
int GetUsedTimeFromStatusFile(const CHAR *szStatusFilePath, int ThreadId);
int GetIntValueFromStatusFile(const CHAR *szStatusFilePath, const CHAR *szKey);