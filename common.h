#pragma once

#include <Windows.h>

typedef enum _CHAT_TYPE
{
	OTHER,
	WECHAT,
	QQ
} CHAT_TYPE,
	*PCHAT_TYPE;

typedef struct _CRACKING_ARGS
{
	// 划片内存映射数据
	PVOID pMappingFileData;
	// 划片内存映射数据大小
	int MappingFileDataSize;
	// 总内存映射数据大小
	ULONGLONG TotalMappingFileDataSize;
	// 爆破密钥长度
	int PasswordSize;
	// 爆破所需数据
	PVOID PageData;
	// 爆破所需数据大小
	int PageDataSize;
	// 爆破函数
	BOOL(*CheckingFunction) (BYTE *, int, BYTE *, int);
	// 密钥过滤函数
	BOOL(*FilterPosFunction) (BYTE *);
	// 线程终止事件
	HANDLE hStopEvent;
	// 线程ID
	int ThreadId;
	// 总线程数
	int ThreadNum;
	// 单次爆破开始时间
	ULONGLONG StartTime;
	// 任务总用时
	ULONGLONG TotallyUsedTime;
	// 爆破密码保存路径
	CHAR szPasswordFilePath[MAX_PATH];
	// 任务目录路径
	CHAR szTaskDir[MAX_PATH];
	// 爆破软件类型
	CHAT_TYPE ChatType;
	// 是否从旧任务恢复
	BOOL blResume;
} CRACKING_ARGS, *PCRACKING_ARGS;

#define SQLITE_FILE_HEADER "SQLite format 3"
#define SQLITE_FILE_HEADER_SIZE 16

VOID DeleteDirectory(const CHAR *Path);
BOOL CheckSQLiteDBHeader(const char *szDBFilePath);
BOOL CrackingDBFile(LPVOID pMappingFileData, LARGE_INTEGER FileSize, BYTE *PageData, CHAT_TYPE ChatType, const CHAR *szPasswordFilePath, int ThreadNum, BOOL blResume);