#include "WeChat.h"

#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Ws2_32.lib")

int main(int argc, char** argv)
{
	CrackWeChatMsgDBFile("I:\\WorkProject2022\\ChatShadow\\ChatShadow\\ChatShadow\\Data\\WeChat.DMP", "I:\\WorkProject2022\\ChatShadow\\ChatShadow\\ChatShadow\\Data\\MSG0.db",
		"I:\\WorkProject2022\\ChatShadow\\ChatShadow\\ChatShadow\\Data\\MSG0_DE.db", "I:\\WorkProject2022\\ChatShadow\\ChatShadow\\ChatShadow\\Data\\Password", 8);
	return 0;
}