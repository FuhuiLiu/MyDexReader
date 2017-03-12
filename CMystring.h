#pragma once
#include <stdio.h>

class CMyString  
{
public:
	CMyString();
    CMyString(const char *pszString);
    CMyString(const CMyString &obj);
	~CMyString();
    char *GetString() const; // 返回存储的字符串
    int GetBuffSize() const; // 获得缓冲区大小
    unsigned int GetBuff() const; // 返回buff地址
    int GetLength() const; // 获得字符串长度
    bool SetString(const char *pszString); // 设置字符串
    bool StrCat(const char *pszString); // 连接指定的字符串
    bool StrCat(const CMyString &str); // 连接相同类的字符串
    bool StrCat(const char ch); // 连接单个字符
    bool IsEmpty() const; // 判断是否为空串
    void MakeUpper(); // 小写转大写
    void MakeLower(); // 大写转小写
    void MakeReverse(); // 反转字符串
    bool Replace(const char chOld, const char chNew); // 用新字符替换指定的字符
    bool Replace(const char *pszOld, const char *pszNew); // 用新字符串替换旧字符串
    int ReverseFind(const char chToFind) const; // 查找返回最后匹配的字符下标(正常阅读)
    int Remove(const char chRemove); // 从字符串中删除所有的指定的字符
    bool Insert(int nIndex, const char chInsert); // 指定位置插入单个字符
    bool Insert(int nIndex, const char *szInsert); // 指定位置插入字符串
    int Delete(int nIndex, int nCount = 1); // 删除指定位置起，共count个字符，默认1个字符
    int Find(const char chToFind) const; // 查找单个字符 找到就返回下标，否则返回-1
    int Find(const char* pszToFind) const; // 查找字符串 找到就返回下标，否则返回-1
    int Find(const char chToFind, int nStart) const; // 指定位置开始查找单个字符 找到就返回下标，否则返回-1
    int Find(const char* pszToFind, int nStart) const; // 指定位置开始查找字符串 找到就返回下标，否则返回-1
	operator char*();
private:
    char *m_pszBuff; // 动态申请的字符串内存存储地址
    int m_nBuffSize; // 动态申请的空间大小
    int m_nLength; // 存储的字符串长度
    void Init(); // 初始化
    void UnInit(); // 释放资源
    int MyStrLen(const char * pszString) const; // 
    char *  MyStrCpy(char * pszDest, const char * pszSour); // 
    int IndistinctSearch(const char *pszToSearch, int nStart = 0) const; // 指定位置查找字符串，默认开始下标0
    int WholeWordSearch(const char *SearchStr, int nStart = 0) const;//全字匹配查询，默认开始下标0
};
