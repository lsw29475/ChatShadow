#pragma once

#include <Windows.h>

typedef enum _CHAT_TYPE
{
	WECHAT
} CHAT_TYPE, *PCHAT_TYPE;

#define SQLITE_FILE_HEADER "SQLite format 3" 
#define SQLITE_FILE_HEADER_SIZE 16

VOID DeleteDirectory(const CHAR *Path);
BOOL CheckSQLiteDBHeader(const char* szDBFilePath);
BOOL CrackingDBFile(LPVOID pMappingFileData, LARGE_INTEGER FileSize, BYTE *PageData, CHAT_TYPE ChatType, const CHAR* szPasswordFilePath, int ThreadNum);