#pragma once

#include "common.h"

VOID SaveCrackingStatus(CRACKING_ARGS *pCrackingArgs, int Pos);
CHAT_TYPE GetChatTypeFromStatusFile(const CHAR* szStatusFilePath);
int GetThreadNumFromStatusFile(const CHAR* szStatusFilePath);
int GetLastPosFromStatusFile(const CHAR* szStatusFilePath, int ThreadId);
