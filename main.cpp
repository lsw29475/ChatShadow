#include "task.h"

#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Ws2_32.lib")

int main(int argc, char **argv)
{
	CRACK_TASK CrackTask;
	memset(&CrackTask, 0, sizeof(CRACK_TASK));
	BOOL blResume = FALSE;

	for (int i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "-M") == 0 && (i + 1) < argc)
		{
			strncpy_s(CrackTask.szMemoryFilePath, argv[++i], sizeof(CrackTask.szMemoryFilePath) - 1);
		}
		else if (strcmp(argv[i], "-D") == 0 && (i + 1) < argc)
		{
			strncpy_s(CrackTask.szMsgDBFilePath, argv[++i], sizeof(CrackTask.szMsgDBFilePath) - 1);
		}
		else if (strcmp(argv[i], "-T") == 0 && (i + 1) < argc)
		{
			strncpy_s(CrackTask.szTaskDir, argv[++i], sizeof(CrackTask.szTaskDir) - 1);
		}
		else if (strcmp(argv[i], "-A") == 0 && (i + 1) < argc)
		{
			if (strcmp(argv[i + 1], "WECHAT") == 0)
			{
				CrackTask.TaskType = WECHAT;
			}
			else if (strcmp(argv[i + 1], "QQ") == 0)
			{
				CrackTask.TaskType = QQ;
			}
			i++;
		}
		else if (strcmp(argv[i], "-N") == 0 && (i + 1) < argc)
		{
			CrackTask.ThreadNum = atoi(argv[++i]);
		}
		else if (strcmp(argv[i], "-R") == 0)
		{
			blResume = TRUE;
		}
	}

	if (blResume)
	{
		ResumeCrackTask(CrackTask.szTaskDir);
	}
	else
	{
		CreateNewCrackTask(&CrackTask);
	}

	return 0;
}