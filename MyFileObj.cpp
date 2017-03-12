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
//������  �� ~CMyFileObj
//�������ܣ� ��������ʱ�رմ򿪵���Դ
//����    �� 
//����ֵ  �� TRUE
//////////////////////////////////////////////////////////////////////////
CMyFileObj::~CMyFileObj()
{
    MyRelease();
}

//////////////////////////////////////////////////////////////////////////
//������  �� MyCloseFile
//�������ܣ� ��ʽ���ùرմ򿪵���Դ
//����    �� 
//����ֵ  �� TRUE
//////////////////////////////////////////////////////////////////////////
BOOL CMyFileObj::MyCloseFile()
{
    MyRelease();
    return TRUE;
}

//////////////////////////////////////////////////////////////////////////
//������  �� MyOpenFile
//�������ܣ� �򿪶�Ӧ��·���ļ�
//����    �� strFilePath            - �ļ�·��
//����    �� dwDesiredAccess        - Ĭ���Զ���дģʽ��
//����    �� dwShareMode            - Ĭ�Ϲ������ʽ
//����    �� dwCreationDisposition  - Ĭ�ϴ򿪴��ڵ��ļ�
//����    �� dwFlagsAndAttributes   - Ĭ���ļ���������
//����ֵ  �� TRUE
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
//������  �� MyGetFileHandle
//�������ܣ� ��ȡ�򿪵��ļ���� 
//����    �� 
//����ֵ  �� �򿪵��ļ���� 
//////////////////////////////////////////////////////////////////////////
HANDLE CMyFileObj::MyGetFileHandle()
{
    return m_hFile;
}

//////////////////////////////////////////////////////////////////////////
//������  �� MyGetFileSize
//�������ܣ� ��ȡ��ǰ�ļ��Ĵ�С 
//����    �� ��
//����ֵ  �� �ɹ������ļ���С�����򷵻�INVALID_FILE_SIZE 
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
//������  �� MyReSetFileSize
//�������ܣ� �����ļ����� 
//����    �� dwNewSize
//����ֵ  �� �ɹ�����TRUE��ʧ�ܷ���FALSE
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
//������  �� MyReadFile
//�������ܣ� ��ȡ�ļ�����
//����    �� pszBuf             - ��ȡ���ݴ�ŵ�ַbuf
//����    �� dwReadLength       - Ҫ��ȡ�ĳ���
//����    �� dwReadBeginAddr    - ָ����ȡ�Ŀ�ʼ��ַ��Ĭ��Ϊ�ļ�ͷ
//����ֵ  �� �ɹ����ض�ȡ���ֽ�����ʧ�ܷ���NULL 
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
//������  �� MyRelease
//�������ܣ� �رմ��ļ���� 
//����    �� 
//����ֵ  �� TRUE 
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
//������  �� MySetFilePoint
//�������ܣ� �����ļ�ָ��
//����    �� dwNewPoint    - ָ��Ҫ�ƶ��ĳ���
//����    �� dwMoveMethod  - �ƶ���ʽ��Ĭ��Ϊ�ļ�ͷΪ��׼
//����ֵ  �� �ɹ�TRUE��ʧ��FALSE
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