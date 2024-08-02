#pragma once

#include <Windows.h>

#define QQ_PAGE_SIZE 8192

// 密钥长度
#define QQ_PASSWORD_SIZE 16
// 校验密钥长度
#define QQ_CHECK_PASSWORD_SIZE 272
// 打印输出间隔
#define QQ_PROGRESS_INTERVAL 10000

// 爆破QQ数据库文件密码并解密
BOOL CrackQQMsgDBFile(const CHAR *szMemoryFilePath, const CHAR *szQQMsgDBFilePath, const CHAR *szDecQQMsgDBFilePath, const CHAR *szPasswordFilePath, int ThreadNum, BOOL blResume);
BOOL DecryptQQMsgDBFile(BYTE *Password, const CHAR *szQQMsgDBFilePath, const CHAR *szDecDBFilePath);
BOOL CheckingQQMsgDBPassword(BYTE *CheckingData, int CheckingDataLength, BYTE *DBData, int DBDataLength);
// 过滤QQ密钥检测函数
BOOL FilterQQPos(BYTE *Pos);
// 打印并保存密钥
VOID PrintAndSaveQQMsgDBPassword(BYTE *Pos, const CHAR *szPasswordFilePath);