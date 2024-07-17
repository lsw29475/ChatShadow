#include "status.h"

#include <iostream>
#include <fstream>
#include <string>
#include <nlohmann/json.hpp>

#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

using json = nlohmann::json;

HANDLE g_hMutex = NULL;

BOOL ReadStatusFile(const CHAR *szStatusFilePath, json &JsonData)
{
    std::ifstream inputFile(szStatusFilePath);
    if (!inputFile.is_open())
    {
        printf("open %s fail\n", szStatusFilePath);
        return false;
    }

    inputFile >> JsonData;
    inputFile.close();
    return true;
}

BOOL WriteStatusFile(const CHAR *szStatusFilePath, json JsonData)
{
    std::ofstream outputFile(szStatusFilePath);
    if (!outputFile.is_open())
    {
        printf("open %s fail\n", szStatusFilePath);
        return false;
    }

    outputFile << JsonData.dump(4);
    outputFile.close();
    return true;
}

VOID SaveCrackingStatus(CRACKING_ARGS *pCrackingArgs, int Pos)
{
    CHAR szStatusFilePath[MAX_PATH] = {0x00};
    json JsonData;

    if (g_hMutex == NULL)
    {
        g_hMutex = CreateMutexA(NULL, FALSE, "Global\\CrackingStatusMutex");
        if (g_hMutex == NULL)
        {
            return;
        }
    }

    DWORD dwWaitResult = WaitForSingleObject(g_hMutex, INFINITE);
    if (dwWaitResult != WAIT_OBJECT_0)
    {
        return;
    }

    sprintf_s(szStatusFilePath, "%s\\Status.txt", pCrackingArgs->szTaskDir);
    if (!PathFileExistsA(szStatusFilePath))
    {
        JsonData["ThreadNum"] = std::to_string(pCrackingArgs->ThreadNum);
        JsonData["TaskType"] = std::to_string(pCrackingArgs->ChatType);
        std::string key = "Thread" + std::to_string(pCrackingArgs->ThreadId);
        JsonData[key] = std::to_string(Pos);
        WriteStatusFile(szStatusFilePath, JsonData);
    }
    else
    {
        ReadStatusFile(szStatusFilePath, JsonData);
        std::string key = "Thread" + std::to_string(pCrackingArgs->ThreadId);
        JsonData[key] = std::to_string(Pos);
        WriteStatusFile(szStatusFilePath, JsonData);
    }

    ReleaseMutex(g_hMutex);
}

CHAT_TYPE GetChatTypeFromStatusFile(const CHAR *szStatusFilePath)
{
    json JsonData;
    if (!ReadStatusFile(szStatusFilePath, JsonData))
    {
        return OTHER;
    }

    try
    {
        return (CHAT_TYPE)std::stoi(JsonData["TaskType"].get<std::string>());
    }
    catch (const std::exception &e)
    {
        return OTHER;
    }
}

int GetThreadNumFromStatusFile(const CHAR *szStatusFilePath)
{
    json JsonData;
    if (!ReadStatusFile(szStatusFilePath, JsonData))
    {
        return -1;
    }

    try
    {
        return std::stoi(JsonData["ThreadNum"].get<std::string>());
    }
    catch (const std::exception &e)
    {
        return -1;
    }
}

int GetLastPosFromStatusFile(const CHAR *szStatusFilePath, int ThreadId)
{
    json JsonData;
    if (!ReadStatusFile(szStatusFilePath, JsonData))
    {
        return -1;
    }

    try
    {
        std::string key = "Thread" + std::to_string(ThreadId);
        return std::stoi(JsonData[key].get<std::string>());
    }
    catch (const std::exception &e)
    {
        return -1;
    }
}