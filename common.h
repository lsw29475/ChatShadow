#pragma once

#include <Windows.h>

typedef enum _CHAT_TYPE
{
	OTHER,
	WECHAT
} CHAT_TYPE, *PCHAT_TYPE;

typedef struct _CRACKING_ARGS
{
	PVOID pMappingFileData;
	int MappingFileDataSize;
	ULONGLONG TotalMappingFileDataSize;
	int PasswordSize;
	PVOID PageData;
	int PageDataSize;
	BOOL(*CheckingFunction)
	(BYTE *, int, BYTE *, int);
	HANDLE hStopEvent;
	int ThreadId;
	int ThreadNum;
	ULONGLONG StartTime;
	CHAR szPasswordFilePath[MAX_PATH];
	CHAR szTaskDir[MAX_PATH];
	CHAT_TYPE ChatType;
	BOOL blResume;
} CRACKING_ARGS, *PCRACKING_ARGS;

#define SQLITE_FILE_HEADER "SQLite format 3" 
#define SQLITE_FILE_HEADER_SIZE 16

VOID DeleteDirectory(const CHAR *Path);
BOOL CheckSQLiteDBHeader(const char* szDBFilePath);
BOOL CrackingDBFile(LPVOID pMappingFileData, LARGE_INTEGER FileSize, BYTE *PageData, CHAT_TYPE ChatType, const CHAR* szPasswordFilePath, int ThreadNum, BOOL blResume);