// MyFileObj.cpp: implementation of the CMyFileObj class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "MyFileObj.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CMyFileObj::CMyFileObj()
{
    m_hFile = INVALID_HANDLE_VALUE;
}

//////////////////////////////////////////////////////////////////////////
//函数名  ： ~CMyFileObj
//函数功能： 对象析构时关闭打开的资源
//参数    ： 
//返回值  ： TRUE
//////////////////////////////////////////////////////////////////////////
CMyFileObj::~CMyFileObj()
{
    MyRelease();
}

//////////////////////////////////////////////////////////////////////////
//函数名  ： MyCloseFile
//函数功能： 显式调用关闭打开的资源
//参数    ： 
//返回值  ： TRUE
//////////////////////////////////////////////////////////////////////////
BOOL CMyFileObj::MyCloseFile()
{
    MyRelease();
    return TRUE;
}

//////////////////////////////////////////////////////////////////////////
//函数名  ： MyOpenFile
//函数功能： 打开对应的路径文件
//参数    ： strFilePath            - 文件路径
//参数    ： dwDesiredAccess        - 默认以读、写模式打开
//参数    ： dwShareMode            - 默认共享读方式
//参数    ： dwCreationDisposition  - 默认打开存在的文件
//参数    ： dwFlagsAndAttributes   - 默认文件属性正常
//返回值  ： TRUE
//////////////////////////////////////////////////////////////////////////
BOOL CMyFileObj::MyOpenFile(string strFilePath, 
                              DWORD dwDesiredAccess, 
                              DWORD dwShareMode,
                              DWORD dwCreationDisposition,
                              DWORD dwFlagsAndAttributes)
{
    m_hFile = ::CreateFile(strFilePath.c_str(), \
                         dwDesiredAccess, 
                         dwShareMode, 
                         NULL, 
                         dwCreationDisposition, 
                         dwFlagsAndAttributes, NULL);
    if(m_hFile != INVALID_HANDLE_VALUE)
    {

        return TRUE;
    }
    return FALSE;
}

//////////////////////////////////////////////////////////////////////////
//函数名  ： MyGetFileHandle
//函数功能： 获取打开的文件句柄 
//参数    ： 
//返回值  ： 打开的文件句柄 
//////////////////////////////////////////////////////////////////////////
HANDLE CMyFileObj::MyGetFileHandle()
{
    return m_hFile;
}

//////////////////////////////////////////////////////////////////////////
//函数名  ： MyGetFileSize
//函数功能： 获取当前文件的大小 
//参数    ： 无
//返回值  ： 成功返回文件大小，否则返回INVALID_FILE_SIZE 
//////////////////////////////////////////////////////////////////////////
DWORD CMyFileObj::MyGetFileSize() const 
{
    if (m_hFile == INVALID_HANDLE_VALUE)
    {
        return NULL;
    }
    return GetFileSize(m_hFile, NULL);
}

//////////////////////////////////////////////////////////////////////////
//函数名  ： MyReSetFileSize
//函数功能： 设置文件长度 
//参数    ： dwNewSize
//返回值  ： 成功返回TRUE，失败返回FALSE
//////////////////////////////////////////////////////////////////////////
BOOL CMyFileObj::MyReSetFileSize(DWORD dwNewSize)
{
    if (SetFilePointer(m_hFile, dwNewSize, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
    {
        if (SetEndOfFile(m_hFile))
        {
            return TRUE;
        }
    }
    return FALSE;
}

//////////////////////////////////////////////////////////////////////////
//函数名  ： MyReadFile
//函数功能： 读取文件内容
//参数    ： pszBuf             - 读取数据存放地址buf
//参数    ： dwReadLength       - 要读取的长度
//参数    ： dwReadBeginAddr    - 指定读取的开始地址，默认为文件头
//返回值  ： 成功返回读取的字节数，失败返回NULL 
//////////////////////////////////////////////////////////////////////////
DWORD CMyFileObj::MyReadFile(TCHAR *pszBuf, DWORD dwReadLength, DWORD dwReadBeginAddr)
{
    DWORD dwReaded = 0;
    BOOL bRet = FALSE;
    if(dwReadBeginAddr != NULL)
    {
        bRet = MySetFilePoint(dwReadBeginAddr);
        if (bRet == FALSE)
        {
            return dwReaded;
        }
    }
    ReadFile(m_hFile, pszBuf, dwReadLength, &dwReaded, NULL);
    return dwReaded;
}

//////////////////////////////////////////////////////////////////////////
//函数名  ： MyRelease
//函数功能： 关闭打开文件句柄 
//参数    ： 
//返回值  ： TRUE 
//////////////////////////////////////////////////////////////////////////
BOOL CMyFileObj::MyRelease()
{
    if(m_hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(m_hFile);
        m_hFile = INVALID_HANDLE_VALUE;
    }
    return TRUE;
}

//////////////////////////////////////////////////////////////////////////
//函数名  ： MySetFilePoint
//函数功能： 设置文件指针
//参数    ： dwNewPoint    - 指定要移动的长度
//参数    ： dwMoveMethod  - 移动方式，默认为文件头为基准
//返回值  ： 成功TRUE，失败FALSE
//////////////////////////////////////////////////////////////////////////
BOOL CMyFileObj::MySetFilePoint(DWORD dwNewPoint, DWORD dwMoveMethod)
{
    if (m_hFile == INVALID_HANDLE_VALUE)
    {
        return NULL;
    }
    DWORD dwRet = SetFilePointer(m_hFile, dwNewPoint, NULL, dwMoveMethod);
    if (dwRet == INVALID_SET_FILE_POINTER)
    {
        return FALSE;
    }
    return TRUE;
}