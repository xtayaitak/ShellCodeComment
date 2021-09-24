// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "framework.h"
#include "od/Plugin.h"
#include "VMQuery.h"
#include <vector>
#include <TlHelp32.h>
#include "Toolhelp.h"
#include <Psapi.h>
#include "spdlog/spdlog.h"
#include "spdlog/sinks/rotating_file_sink.h"
#include "resource.h"
#include "fmt/format.h"
#include <fstream>
#include <map>
#include "FileTool.h"
#include "StringTool.h"

HINSTANCE g_cur_dll_instalce = NULL;

#pragma comment(lib,"OLLYDBG.LIB")


int ODBG_Plugindata(char* shortname)
{
    strcpy(shortname, "ShellCodeComment");
    return PLUGIN_VERSION;
}

int ODBG_Plugininit(int ollydbgversion, HWND hw, ulong* features)
{

    return 0;
}

int ODBG_Pluginmenu(int origin, char data[4096], void* item)
{
    if (origin != PM_MAIN)
        return 0;                          // No pop-up menus in OllyDbg's windows
    strcpy(data, "0 &ShellCodeComment\tAlt+F1|1 &Help,2 &About,3 &TestFindComment,4 &TestInsertComment,5 &LoadShellCode Comment,6 &SaveShellCode Comment");
    return 1;
}

void ODBG_Pluginreset(void)
{
    auto status = _Getstatus();
    if (status != STAT_NONE) {

    }
}
void LoadShellCodeComment();
void SaveShellCodeComment();

void ODBG_Pluginaction(int origin, int action, void* item)
{
    if (origin == PM_MAIN) {
        if (action == 3) {
            ulong value = 0;
            char title[] = "请输入要查找的地址";
            if (0 == _Getlong(title, &value, 4, 0, 0)) {
                char comment[256] = { 0 };
                if (_Findname(value, NM_COMMENT, comment) > 0) {
                    ::MessageBoxA(NULL, "提示", comment, MB_OK);
                }
            }
        }
        else if (action == 4) {
            ulong value = 0;
            char title[] = "请输入要插入的地址";
            if (0 == _Getlong(title, &value, 4, 0, 0)) {
                char title2[] = "请输入要写入的字符串";
                char text[256] = { 0 };
                if (_Gettext(title2, text, 0, NM_NONAME, 0) > 0) {
                    _Insertname(value, NM_COMMENT, text);
                }
            }
        }
        else if (action == 5) {
            LoadShellCodeComment();
        }
        else if (action == 6) {
            SaveShellCodeComment();
        }
    }
}
void ODBG_Pluginsaveudd(t_module* pmod, int ismainmodule)
{

}

int ODBG_Pluginclose(void)
{
    return 0;
}
void ODBG_Plugindestroy(void)
{

}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        g_cur_dll_instalce = hModule;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

std::wstring GetMyPluginDataPath()
{
    static std::wstring path = []() -> std::wstring{
        std::wstring s = file_tools::GetCurrentAppPath() + L"ShellcodeComment\\"; 
        if (!file_tools::FileExist(s)) {
            file_tools::CreateDirectoryNested(s);
        }
        return s;
    }();
    return path;
}



struct MemoryInfo {
    DWORD base_addr = 0;
    size_t size = 0;
};

std::vector<MemoryInfo> GetShellCodeMemoryList()
{
    CToolhelp toolhelp;
    DWORD pid = (DWORD)_Plugingetvalue(VAL_PROCESSID);
    if (pid == 0) {
        return {};
    }
    toolhelp.CreateSnapshot(TH32CS_SNAPALL, pid);
    HANDLE hProcess = (HANDLE)_Plugingetvalue(VAL_HPROCESS);
    auto HasMappedModule = [&toolhelp, &hProcess](VMQUERY* pvmq) {
        if (pvmq->dwRgnStorage == MEM_PRIVATE && (pvmq->dwRgnProtection & PAGE_EXECUTE_READWRITE) > 0) {
            MODULEENTRY32 me = { 0 };
            me.dwSize = sizeof(MODULEENTRY32);
            if (toolhelp.ModuleFind(pvmq->pvRgnBaseAddress, &me) && _tcslen(me.szExePath) > 0) {
                return true;
            }
            else {
                TCHAR module_name[256];
                if (GetMappedFileName(hProcess, pvmq->pvRgnBaseAddress, module_name, MAX_PATH) > 0) {
                    return true;
                }
            }
        }
        return false;
    };

    BOOL bOk = TRUE;
    DWORD pvAddress = NULL;
    std::vector<MemoryInfo> result;
    while (bOk) {
        VMQUERY vmq;
        bOk = VMQuery(hProcess, (LPCVOID)pvAddress, &vmq);
        if (bOk) {
            if (vmq.dwRgnStorage == MEM_PRIVATE && (vmq.dwRgnProtection & PAGE_EXECUTE_READWRITE) > 0 && !HasMappedModule(&vmq)) {
                MemoryInfo mem_info;
                mem_info.base_addr = (DWORD)vmq.pvRgnBaseAddress;
                mem_info.size = vmq.RgnSize;
                result.push_back(mem_info);
            }
            pvAddress = (DWORD)vmq.pvRgnBaseAddress + vmq.RgnSize;
        }
    }
    return result;
}
std::vector<unsigned char> ReadMem(LPVOID addr, size_t size)
{
    HANDLE hProcess = (HANDLE)_Plugingetvalue(VAL_HPROCESS);
    std::unique_ptr<unsigned char[]> feature_buffer(new unsigned char[size]);
    SIZE_T read_size = 0;
    if (::ReadProcessMemory(hProcess, addr, (LPVOID)feature_buffer.get(), size, &read_size) && read_size == size) {
        std::vector<unsigned char> readed(size);
        memcpy(readed.data(), feature_buffer.get(), size);
        return readed;
    }
    return {};
}
struct ShellCodeFeature {
    DWORD feature_offset = 0;
    std::vector<unsigned char> feature_code;
};

struct ShellCodeComment {
    DWORD offset = 0;
    std::wstring text;
};


std::vector<ShellCodeComment> GetShellCodeComment(const MemoryInfo & vmq)
{
    std::vector<ShellCodeComment>  comments;
    char commen_text[256] = { 0 };
    if (_Findname((ulong)vmq.base_addr, NM_COMMENT, commen_text) > 0) {
        ShellCodeComment comment;
        comment.offset = 0;
        comment.text = string_tool::CharToWide(commen_text);
        comments.push_back(comment);
    }

    ulong addr = 0;
    while (addr = _Findnextname(commen_text)) {
        if (chINRANGE((ulong)vmq.base_addr, addr, (ulong)vmq.base_addr + vmq.size)) {
            ShellCodeComment comment;
            comment.offset = addr - (ulong)vmq.base_addr;
            comment.text = string_tool::CharToWide(commen_text);
            comments.push_back(comment);
        }
    }
    return comments;
}

struct UserCustomShellCode {
    DWORD size = 0;
    std::wstring name;
    ShellCodeFeature feature;
};
std::vector<UserCustomShellCode> g_user_custom_shellcode_features;



std::wstring BufferToLine(const std::vector<unsigned char>& buffer)
{
    std::wstring s;
    for (auto& ch : buffer) {
        s += fmt::format(L"{:02X}", ch);
    }
    return s;
}
std::vector<unsigned char> HexLineToBuffer(const std::wstring& line)
{
    //450306
    assert(line.length() % 2 == 0);
    std::vector<unsigned char> result;
    for (size_t i = 0; i < line.length() / 2; i++) {
        std::wstring hex_str = line.substr(i * 2, 2);
        result.push_back((unsigned char)std::stoul(hex_str, nullptr, 16));
    }
    return result;
}
void LoadUserCustomShellCodeFeature()
{
    g_user_custom_shellcode_features.clear();
    char process_name[256] = { 0 };
    strcpy(process_name,(char*) _Plugingetvalue(VAL_PROCESSNAME));
    std::wstring file_name = GetMyPluginDataPath() +  string_tool::CharToWide(process_name) + L".shellcode_features";
    auto lines = file_tools::ReadUnicodeFileLines(file_name);
    for (auto& line : lines) {
        auto items =  string_tool::SplitStrByFlag<std::wstring>(line, L"|");
        if (items.size() == 4) {
            size_t shellcode_size = std::stoul(items.at(0),nullptr,16);
            std::wstring name = items.at(1);
            size_t feature_offset = std::stoul(items.at(2),nullptr,16);
            std::vector<unsigned char> feature_code = HexLineToBuffer(items.at(3));

            UserCustomShellCode custum_shellcode_feature;
            custum_shellcode_feature.size = shellcode_size;
            custum_shellcode_feature.name = name;
            custum_shellcode_feature.feature.feature_code = feature_code;
            custum_shellcode_feature.feature.feature_offset = feature_offset;
            g_user_custom_shellcode_features.push_back(custum_shellcode_feature);
        }
    }
}

std::map<DWORD, std::wstring> g_analyzed_custom_shellcode_list;
void AnalyzeCacheShellCodeBase()
{
    auto shell_code_list = GetShellCodeMemoryList();
    for (const auto& shell_code : shell_code_list) {
        for (auto& feature : g_user_custom_shellcode_features) {
            if (shell_code.size == feature.size) {
                auto bytes =  ReadMem((unsigned char*)shell_code.base_addr + feature.feature.feature_offset, feature.feature.feature_code.size());
                if (memcmp(bytes.data(), feature.feature.feature_code.data(), feature.feature.feature_code.size()) == 0) {
                    g_analyzed_custom_shellcode_list[shell_code.base_addr] = feature.name;
                }
            }

        }
    }
}


void SaveUserCustomShellCodeFeature()
{
    char process_name[256] = { 0 };
    strcpy(process_name, (char*)_Plugingetvalue(VAL_PROCESSNAME));
    std::wstring file_name = GetMyPluginDataPath() + string_tool::CharToWide(process_name) + L".shellcode_features";

    std::wstring file_content;
    for (auto& feature : g_user_custom_shellcode_features) {
        std::wstring line = fmt::format(L"{:08X}|{}|{:08X}|{}\r\n", feature.size, feature.name, feature.feature.feature_offset,BufferToLine(feature.feature.feature_code));
        file_content += line;
    }
    file_tools::WriteUnicodeFile(file_name, file_content);
}



std::wstring GetUserCustomShellCodeName(DWORD addr) {
    auto iter = g_analyzed_custom_shellcode_list.find(addr);
    if (iter == g_analyzed_custom_shellcode_list.end()) {
        return L"";
    }
    else {
        return iter->second;
    }
}

struct DialogCustomData {
    DWORD base_addr = 0;
    TCHAR name[100];
    DWORD feature_addr_start;
    DWORD feature_code_size;
};

BOOL CALLBACK InputShellCodeFeatureDialogProc(HWND hwndDlg,
    UINT message,
    WPARAM wParam,
    LPARAM lParam)
{
    switch (message)
    {
    case WM_INITDIALOG:
    {
        std::wstring text = fmt::format(L"{:#04x}", ((uint64_t)((DialogCustomData*)lParam)->base_addr));
        SetDlgItemText(hwndDlg, IDC_EDIT_BASE_ADDR, text.c_str());
        ::SetWindowLongPtr(hwndDlg, GWLP_USERDATA, lParam);
        break;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDOK:
        {
            TCHAR feature_name[100] = { 0 };
            TCHAR szstart_addr[100] = { 0 };
            TCHAR szend_addr[100] = { 0 };
            GetDlgItemText(hwndDlg, IDC_EDIT_NAME, feature_name, 100);
            GetDlgItemText(hwndDlg, IDC_EDIT_FEATURE_START_ADDR, szstart_addr,100);
            GetDlgItemText(hwndDlg, IDC_EDIT_FEATURE_END_ADDR, szend_addr,100);
            DWORD start_addr = std::stoul(szstart_addr, nullptr, 16);
            DWORD end_addr = std::stoul(szend_addr, nullptr, 16);
            DWORD feature_code_size = end_addr - start_addr;
            if (_tcslen(feature_name) > 0 && start_addr >= 0 && feature_code_size > 0) {
                DialogCustomData * data = (DialogCustomData*)::GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
                _tcscpy(data->name, feature_name);
                data->feature_addr_start = start_addr;
                data->feature_code_size = feature_code_size;
                ::EndDialog(hwndDlg, IDOK);
            }
            else {
                ::MessageBoxW(hwndDlg, L"Input Error", NULL, MB_OK);
            }
            break;
        }
        case IDCANCEL:
            ::EndDialog(hwndDlg, IDCANCEL);
            break;
        }
        break;
    default:
        break;
    }
    return 0;
}

bool DialogInputAddShellCodeFeature(DWORD shellcode_base_addr,DWORD shellcode_size,std::wstring & name)
{
    //填充用户在意的shellcode
    HWND main_window = (HWND)_Plugingetvalue(VAL_HWCLIENT);

    DialogCustomData dlg_data;
    dlg_data.base_addr = shellcode_base_addr;
    INT_PTR dlg_ret = DialogBoxParam(g_cur_dll_instalce, MAKEINTRESOURCE(IDD_DIALOG_INPUT_SHELLCODE_FEATURE), main_window, InputShellCodeFeatureDialogProc,(LPARAM)&dlg_data);
    if (dlg_ret == IDOK) {
        if (std::find_if(g_user_custom_shellcode_features.begin(), g_user_custom_shellcode_features.end(), [&dlg_data](const UserCustomShellCode& s) {return s.name == dlg_data.name; }) != g_user_custom_shellcode_features.end()) {
            ::MessageBox(main_window, L"ShellCode名称重复", NULL, MB_OK);
            return false;
        }
        else {
            HANDLE hProcess = (HANDLE)_Plugingetvalue(VAL_HPROCESS);

            std::unique_ptr<unsigned char[]> feature_buffer (new unsigned char[dlg_data.feature_code_size]);
            SIZE_T read_size = 0;
            if (::ReadProcessMemory(hProcess, (LPCVOID)(dlg_data.feature_addr_start), (LPVOID)feature_buffer.get(), dlg_data.feature_code_size, &read_size) && read_size == dlg_data.feature_code_size) {
                UserCustomShellCode custom_shellcode;
                custom_shellcode.size = shellcode_size;
                custom_shellcode.name = dlg_data.name;
                for (size_t i = 0; i < dlg_data.feature_code_size; i++) {
                    custom_shellcode.feature.feature_code.push_back(feature_buffer[i]);
                }
                custom_shellcode.feature.feature_offset = dlg_data.feature_addr_start - dlg_data.base_addr;
                name = custom_shellcode.name;

                g_user_custom_shellcode_features.push_back(custom_shellcode);
                SaveUserCustomShellCodeFeature();
                return true;
            }
            else {
                return false;
            }
        }
    }
    else{
        return false;
    }
}


std::wstring GetCommentSavePath(const std::wstring & exe_name)
{
    return GetMyPluginDataPath() + exe_name + L"\\";
}


void LoadShellCodeComment()
{
    LoadUserCustomShellCodeFeature();
    AnalyzeCacheShellCodeBase();

    char process_name[256] = { 0 };
    strcpy(process_name, (char*)_Plugingetvalue(VAL_PROCESSNAME));
    std::wstring path = GetCommentSavePath(string_tool::CharToWide(process_name));
    if (!file_tools::FileExist(path)) {
        file_tools::CreateDirectoryNested(path);
    }

    auto shell_code_list = GetShellCodeMemoryList();
    for (const auto& vmq : shell_code_list) {
        std::wstring name = GetUserCustomShellCodeName(vmq.base_addr);
        if (name.length() > 0) {
            std::wstring file_name = path + name + L".comment";
            auto lines =  file_tools::ReadUnicodeFileLines(file_name);
            for (const auto& line : lines) {
                auto flag =  line.find('^');
                if (flag == std::wstring::npos) {
                    continue;
                }
                DWORD offset = std::stoul(line.substr(0, flag),nullptr,16);
                std::wstring text = line.substr(flag + 1);

                char ansi_text[256] = { 0 };
                strcpy_s(ansi_text, string_tool::WideToChar(text).c_str());
                _Insertname((ulong)(char*)vmq.base_addr + offset, NM_COMMENT, ansi_text);
            }
        }
    }
}


void SaveShellCodeComment()
{
    //遍历 ShellCode
    //遍历 ShellCode里注释
    //保存注释 怎么标识一个ShellCode? 1.大小 2.特征码（shellcode md5?） 感觉也不行。因为shellcode有些地址每次加载都会被换掉 所以只能自己标识，那就用指定偏移的一段特征码标识吧
    LoadUserCustomShellCodeFeature();
    AnalyzeCacheShellCodeBase();

    char process_name[256] = { 0 };
    strcpy(process_name, (char*)_Plugingetvalue(VAL_PROCESSNAME));
    std::wstring path = GetCommentSavePath(string_tool::CharToWide(process_name));
    if (!file_tools::FileExist(path)) {
        file_tools::CreateDirectoryNested(path);
    }

    auto shell_code_list = GetShellCodeMemoryList();
    for (const auto& vmq : shell_code_list) {
        std::vector<ShellCodeComment> comments = GetShellCodeComment(vmq);
        if (comments.size() > 0) {
            std::wstring name = GetUserCustomShellCodeName(vmq.base_addr);
            if (name.length() == 0) {
                if (!DialogInputAddShellCodeFeature(vmq.base_addr, vmq.size, name)) {
                    continue;
                }
                else {
                    g_analyzed_custom_shellcode_list[vmq.base_addr] = name;
                }
            }
            std::wstring file_name = path + name + L".comment";
            std::wstring file_content;
            for (const auto& comment : comments) {
                std::wstring line = fmt::format(L"{:08X}^{}\r\n", comment.offset, comment.text);
                file_content += line;

            }
            file_tools::WriteUnicodeFile(file_name, file_content);
        }
    }
}