#include "WeChat.h"

#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Ws2_32.lib")

int main(int argc, char** argv)
{
	CrackWeChatMsgDBFile("I:\\WorkProject2022\\ChatShadow\\ChatShadow\\ChatShadow\\Data\\WeChat_lsj.DMP", "I:\\WorkProject2022\\ChatShadow\\ChatShadow\\ChatShadow\\Data\\Applet_lsj.db",
		"I:\\WorkProject2022\\ChatShadow\\ChatShadow\\ChatShadow\\Data\\Applet_lsj_DE.db", "I:\\WorkProject2022\\ChatShadow\\ChatShadow\\ChatShadow\\Data\\Password_lsj", 8);
	return 0;
}