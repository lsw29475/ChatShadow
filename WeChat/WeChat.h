#pragma once

#include <Windows.h>

// 哈希迭代次数
#define WECHAT_DEFAULT_ITER 64000
// 数据库第一页起始盐长度
#define WECHAT_SALT_SIZE 16
// 数据库页大小
#define WECHAT_PAGE_SIZE 4096
// 数据库页末尾保留HashKey长度
#define WECHAT_PAGE_REVERSED 32
// 数据库页末尾保留Iv长度
#define WECHAT_PAGE_IV_SIZE 16
// 密钥长度
#define WECHAT_PASSWORD_SIZE 32
// 校验密码长度
#define WECHAT_CHECK_PASSWORD_SIZE 32
// 打印输出间隔
#define WECHAT_PROGRESS_INTERVAL 1000

// 爆破微信数据库文件密码并解密
BOOL CrackWeChatMsgDBFile(const CHAR *szMemoryFilePath, const CHAR *szWeChatMsgDBFilePath, const CHAR *szDecWeChatMsgDBFilePath, const CHAR *szPasswordFilePath, int ThreadNum, BOOL blResume);
// 解密微信数据库文件
BOOL DecryptWeChatMsgDBFile(BYTE *Password, const CHAR *szWeChatMsgDBFilePath, const CHAR *szDecDBFilePath);
// 检验微信数据库密码
BOOL CheckingWeChatMsgDBPassword(BYTE *CheckingData, int CheckingDataLength, BYTE *DBData, int DBDataLength);
// 过滤微信密钥检测函数
BOOL FilterWeChatPos(BYTE *Pos);
// 打印并保存密钥
VOID PrintAndSaveWeChatMsgDBPassword(BYTE *Pos, const CHAR *szPasswordFilePath);