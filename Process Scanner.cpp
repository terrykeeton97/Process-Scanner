#include "Includes.h"

/*
 * Project: Process Scanner
 *
 * Description: This program lists the loaded modules in a specified process,
 *              along with their start and end addresses. It uses the Windows
 *              module management functions EnumProcessModules and
 *              GetModuleInformation to retrieve information about the loaded
 *              modules. The program prompts the user to enter the name of the
 *              process they want to examine, and then displays a list of the
 *              modules that are currently loaded in that process.
 *
 * Author: Terry Keeton
 * Date: 26/02/2023
 */

int main()
{
    std::cout << "Enter the process name: ";
    std::string process_name;
    std::getline(std::cin, process_name);

    DWORD process_id = 0;
    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32);

    while (process_id == 0)
    {
        std::cout << "Searching for " << process_name << " process..." << std::endl;

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
        if (Process32First(snapshot, &process_entry))
        {
            do
            {
                std::wstring wsExeFile(process_entry.szExeFile);
                std::string szExeFile;
                szExeFile.resize(wsExeFile.size());
                WideCharToMultiByte(CP_UTF8, 0, wsExeFile.c_str(), wsExeFile.size(), &szExeFile[0], szExeFile.size(), NULL, NULL);
                szExeFile.resize(strlen(szExeFile.c_str()));
                if (szExeFile == process_name)
                {
                    process_id = process_entry.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &process_entry));
        }
        CloseHandle(snapshot);
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }

    std::cout << process_name << " process found with ID " << process_id << std::endl;
    std::cout << "" << std::endl;

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process_id);
    if (process != NULL)
    {
        HMODULE modules[1024];
        DWORD num_modules;
        if (EnumProcessModules(process, modules, sizeof(modules), &num_modules))
        {
            for (DWORD i = 0; i < num_modules / sizeof(HMODULE); i++)
            {
                MODULEINFO module_info;
                if (GetModuleInformation(process, modules[i], &module_info, sizeof(MODULEINFO)))
                {
                    char module_name[MAX_PATH];
                    GetModuleFileNameExA(process, modules[i], module_name, sizeof(module_name));
                    std::cout << "Module Name: " << std::setw(20) << module_name << std::endl;
                    std::cout << "Start Address: 0x" << std::setfill('0') << std::setw(8) << std::uppercase << std::hex << (DWORD_PTR)module_info.lpBaseOfDll << std::endl;
                    std::cout << "End Address: 0x" << std::setfill('0') << std::setw(8) << std::uppercase << std::hex << (DWORD_PTR)module_info.lpBaseOfDll + module_info.SizeOfImage << std::endl;
                }
                else
                {
                    std::cout << "Failed to get module information" << std::endl;
                }
            }
        }
        else
        {
            std::cout << "Failed to enumerate process modules" << std::endl;
        }
        CloseHandle(process);
    }
    else
    {
        std::cout << "Failed to open process" << std::endl;
    }
    std::cout << "Press Enter to exit...";
    std::cin.get();
    return 0;
}
   
