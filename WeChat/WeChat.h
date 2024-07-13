#pragma once

#include <Windows.h>

//哈希迭代次数
#define WECHAT_DEFAULT_ITER 64000
//数据库第一页起始盐长度
#define WECHAT_SALT_SIZE 16
//数据库页大小
#define WECHAT_PAGE_SIZE 4096
//数据库页末尾保留HashKey长度
#define WECHAT_PAGE_REVERSED 32
//数据库页末尾保留Iv长度
#define WECHAT_PAGE_IV_SIZE 16
//密钥长度
#define WECHAT_PASSWORD_SIZE 32

BOOL CrackWeChatMsgDBFile(const CHAR* szMemoryFilePath, const CHAR* szWeChatMsgDBFilePath, const CHAR* szDecWeChatMsgDBFilePath, const CHAR* szPasswordFilePath, int ThreadNum);
BOOL DecryptWeChatMsgDBFile(BYTE* Password, const CHAR* szWeChatMsgDBFilePath, const CHAR* szDecDBFilePath);
BOOL CheckingWeChatMsgDBPassword(BYTE* CheckingData, int CheckingDataLength, BYTE* DBData, int DBDataLength);