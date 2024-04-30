#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <regex>
#include "httplib.h"
#include "skCrypter.h"
//用于隐藏控制台窗口
#pragma comment(linker,"/subsystem:\"Windows\" /entry:\"mainCRTStartup\"")
