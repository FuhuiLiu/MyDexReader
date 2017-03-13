#include "MyDexObj.h"
#include "MyFileObj.h"

#ifndef MYDEXSHOWUTILS__H__20170311
#define MYDEXSHOWUTILS__H__20170311

class MyDexShowUtils
{
public:
    MyDexShowUtils();
    void MsgStart(const char* pstr);
    void MsgEnd(const char* pstr);
    void EnterLine();
    void pf(const char* pCt) { printf("%s", pCt); }
    bool init(const char* pDexFilePath);
    void showSignature();

    void showAllString();   //��ʾ�����ַ���
    void showAllType();   //��ʾtype�ַ���
    void showAllProto();  //��ʾ����proto��Ϣ
	void showAllFields();	//��ʾ����field��Ϣ
	void showAllMethods();	//��ʾ����method��Ϣ
	void showAllClasses();	//��ʾ����class��Ϣ

protected:
private:
    CMyFileObj  *m_FileObj;
    char        *m_pNewAddr;
    CMyDexObj   *m_pDexObj;
};

#endif