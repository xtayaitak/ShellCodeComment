﻿// ShellCodeDemo.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>

#include <fstream>
#include <string>

int MyShellCode()
{
	__asm {
		mov ecx,ecx
		mov ecx,ecx
	}

	int test_array1[100];
	for (int i = 0; i < 100; i++) {
		test_array1[i] = i;
	}

	int test_arary2[100];
	for (int i = 0; i < 100; i++) {
		test_arary2[i] = i + 200;
	}

	int test_arary3[100];
	for (int i = 0; i < 100; i++) {
		test_arary3[i] = test_array1[i] + test_arary2[i];
	}
	int sum;
	for (int i = 0; i < 100; i++){
		sum += test_arary3[i];
	}
	return sum;
}



int main()
{


	unsigned char code[] = {
		0x55,0x8B,0xEC,0x81,0xEC,0x84,0x05,0x00,0x00,0x53,0x56,0x57,0x8B,0xC9,0x8B,0xC9,0xC7,0x85,0x6C,0xFE,0xFF,0xFF,0x00,0x00,0x00,0x00,0xEB,0x0F,0x8B,0x85,0x6C,0xFE,
0xFF,0xFF,0x83,0xC0,0x01,0x89,0x85,0x6C,0xFE,0xFF,0xFF,0x83,0xBD,0x6C,0xFE,0xFF,0xFF,0x64,0x7D,0x15,0x8B,0x85,0x6C,0xFE,0xFF,0xFF,0x8B,0x8D,0x6C,0xFE,0xFF,0xFF,
0x89,0x8C,0x85,0x70,0xFE,0xFF,0xFF,0xEB,0xD3,0xC7,0x85,0xD8,0xFC,0xFF,0xFF,0x00,0x00,0x00,0x00,0xEB,0x0F,0x8B,0x85,0xD8,0xFC,0xFF,0xFF,0x83,0xC0,0x01,0x89,0x85,
0xD8,0xFC,0xFF,0xFF,0x83,0xBD,0xD8,0xFC,0xFF,0xFF,0x64,0x7D,0x1A,0x8B,0x85,0xD8,0xFC,0xFF,0xFF,0x05,0xC8,0x00,0x00,0x00,0x8B,0x8D,0xD8,0xFC,0xFF,0xFF,0x89,0x84,
0x8D,0xDC,0xFC,0xFF,0xFF,0xEB,0xCE,0xC7,0x85,0x44,0xFB,0xFF,0xFF,0x00,0x00,0x00,0x00,0xEB,0x0F,0x8B,0x85,0x44,0xFB,0xFF,0xFF,0x83,0xC0,0x01,0x89,0x85,0x44,0xFB,
0xFF,0xFF,0x83,0xBD,0x44,0xFB,0xFF,0xFF,0x64,0x7D,0x29,0x8B,0x85,0x44,0xFB,0xFF,0xFF,0x8B,0x8C,0x85,0x70,0xFE,0xFF,0xFF,0x8B,0x95,0x44,0xFB,0xFF,0xFF,0x03,0x8C,
0x95,0xDC,0xFC,0xFF,0xFF,0x8B,0x85,0x44,0xFB,0xFF,0xFF,0x89,0x8C,0x85,0x48,0xFB,0xFF,0xFF,0xEB,0xBF,0xC7,0x85,0x3C,0xFB,0xFF,0xFF,0x00,0x00,0x00,0x00,0xEB,0x0F,
0x8B,0x85,0x3C,0xFB,0xFF,0xFF,0x83,0xC0,0x01,0x89,0x85,0x3C,0xFB,0xFF,0xFF,0x83,0xBD,0x3C,0xFB,0xFF,0xFF,0x64,0x7D,0x1B,0x8B,0x85,0x3C,0xFB,0xFF,0xFF,0x8B,0x8D,
0x40,0xFB,0xFF,0xFF,0x03,0x8C,0x85,0x48,0xFB,0xFF,0xFF,0x89,0x8D,0x40,0xFB,0xFF,0xFF,0xEB,0xCD,0x8B,0x85,0x40,0xFB,0xFF,0xFF,0x5F,0x5E,0x5B,0x8B,0xE5,0x5D,0xC3
	};

	LPVOID exec = ::VirtualAlloc(NULL, sizeof(code), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	std::cout << "ShellCode Addr:" << exec << std::endl;
	memcpy(exec, code, sizeof(code));
	auto c = MyShellCode();
	std::cout << "ShellCode Result:" <<  c << std::endl;
	auto d = ((int (*)())exec)();
	std::cout << "Real Result:" << c << std::endl;
	system("pause");
	return 0;
}

