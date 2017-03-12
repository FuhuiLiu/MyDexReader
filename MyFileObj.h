// MyFileObj.h: interface for the CMyFileObj class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_MYFILEOBJ_H__F5B6FDB6_B850_430B_8554_7F0BA2DCDB14__INCLUDED_)
#define AFX_MYFILEOBJ_H__F5B6FDB6_B850_430B_8554_7F0BA2DCDB14__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <WINDOWS.H>
#include <iostream>
#include <string>
using namespace std;

#define INVALID_SET_FILE_POINTER ((DWORD)-1)
#define IN
#define OUT

class CMyFileObj  
{
public:
    //函数功能： 关闭打开文件句柄 
    BOOL  MyRelease();
    //函数功能： 读取文件内容
    DWORD MyReadFile(IN OUT TCHAR *pszBuf, \
                     IN DWORD dwReadLength, 
                     IN DWORD dwReadBeginAddr = NULL);
    //函数功能： 设置文件指针
    BOOL MySetFilePoint(IN DWORD dwNewPoint, \
                        IN DWORD dwMoveMethod = FILE_BEGIN);
    //函数功能： 设置文件长度 
    BOOL MyReSetFileSize(IN DWORD dwNewSize);
    //函数功能： 获取当前文件的大小 
    DWORD MyGetFileSize() const ;
    //函数功能： 显式调用关闭打开的资源
    BOOL MyCloseFile();
    //函数功能： 打开对应的路径文件
    BOOL MyOpenFile(IN  string strFilePath, 
                    IN  DWORD dwDesiredAccess = GENERIC_READ | GENERIC_WRITE, 
                    IN  DWORD dwShareMode = FILE_SHARE_READ,
                    IN  DWORD dwCreationDisposition = OPEN_EXISTING,
                    IN  DWORD dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL);
    HANDLE MyGetFileHandle();
    //函数功能： 获取打开的文件句柄 
	CMyFileObj();
	virtual ~CMyFileObj();
private:
    HANDLE m_hFile;
};

#endif // !defined(AFX_MYFILEOBJ_H__F5B6FDB6_B850_430B_8554_7F0BA2DCDB14__INCLUDED_)
