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
    //�������ܣ� �رմ��ļ���� 
    BOOL  MyRelease();
    //�������ܣ� ��ȡ�ļ�����
    DWORD MyReadFile(IN OUT TCHAR *pszBuf, \
                     IN DWORD dwReadLength, 
                     IN DWORD dwReadBeginAddr = NULL);
    //�������ܣ� �����ļ�ָ��
    BOOL MySetFilePoint(IN DWORD dwNewPoint, \
                        IN DWORD dwMoveMethod = FILE_BEGIN);
    //�������ܣ� �����ļ����� 
    BOOL MyReSetFileSize(IN DWORD dwNewSize);
    //�������ܣ� ��ȡ��ǰ�ļ��Ĵ�С 
    DWORD MyGetFileSize() const ;
    //�������ܣ� ��ʽ���ùرմ򿪵���Դ
    BOOL MyCloseFile();
    //�������ܣ� �򿪶�Ӧ��·���ļ�
    BOOL MyOpenFile(IN  string strFilePath, 
                    IN  DWORD dwDesiredAccess = GENERIC_READ | GENERIC_WRITE, 
                    IN  DWORD dwShareMode = FILE_SHARE_READ,
                    IN  DWORD dwCreationDisposition = OPEN_EXISTING,
                    IN  DWORD dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL);
    HANDLE MyGetFileHandle();
    //�������ܣ� ��ȡ�򿪵��ļ���� 
	CMyFileObj();
	virtual ~CMyFileObj();
private:
    HANDLE m_hFile;
};

#endif // !defined(AFX_MYFILEOBJ_H__F5B6FDB6_B850_430B_8554_7F0BA2DCDB14__INCLUDED_)
