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

    void showAllString();   //显示所有字符串
    void showAllType();   //显示type字符串
    void showAllProto();  //显示所有proto信息
protected:
private:
    CMyFileObj  *m_FileObj;
    char        *m_pNewAddr;
    CMyDexObj   *m_pDexObj;
};

#endif