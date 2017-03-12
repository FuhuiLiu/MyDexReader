#pragma once
#include <stdio.h>

class CMyString  
{
public:
	CMyString();
    CMyString(const char *pszString);
    CMyString(const CMyString &obj);
	~CMyString();
    char *GetString() const; // ���ش洢���ַ���
    int GetBuffSize() const; // ��û�������С
    unsigned int GetBuff() const; // ����buff��ַ
    int GetLength() const; // ����ַ�������
    bool SetString(const char *pszString); // �����ַ���
    bool StrCat(const char *pszString); // ����ָ�����ַ���
    bool StrCat(const CMyString &str); // ������ͬ����ַ���
    bool StrCat(const char ch); // ���ӵ����ַ�
    bool IsEmpty() const; // �ж��Ƿ�Ϊ�մ�
    void MakeUpper(); // Сдת��д
    void MakeLower(); // ��дתСд
    void MakeReverse(); // ��ת�ַ���
    bool Replace(const char chOld, const char chNew); // �����ַ��滻ָ�����ַ�
    bool Replace(const char *pszOld, const char *pszNew); // �����ַ����滻���ַ���
    int ReverseFind(const char chToFind) const; // ���ҷ������ƥ����ַ��±�(�����Ķ�)
    int Remove(const char chRemove); // ���ַ�����ɾ�����е�ָ�����ַ�
    bool Insert(int nIndex, const char chInsert); // ָ��λ�ò��뵥���ַ�
    bool Insert(int nIndex, const char *szInsert); // ָ��λ�ò����ַ���
    int Delete(int nIndex, int nCount = 1); // ɾ��ָ��λ���𣬹�count���ַ���Ĭ��1���ַ�
    int Find(const char chToFind) const; // ���ҵ����ַ� �ҵ��ͷ����±꣬���򷵻�-1
    int Find(const char* pszToFind) const; // �����ַ��� �ҵ��ͷ����±꣬���򷵻�-1
    int Find(const char chToFind, int nStart) const; // ָ��λ�ÿ�ʼ���ҵ����ַ� �ҵ��ͷ����±꣬���򷵻�-1
    int Find(const char* pszToFind, int nStart) const; // ָ��λ�ÿ�ʼ�����ַ��� �ҵ��ͷ����±꣬���򷵻�-1
	operator char*();
private:
    char *m_pszBuff; // ��̬������ַ����ڴ�洢��ַ
    int m_nBuffSize; // ��̬����Ŀռ��С
    int m_nLength; // �洢���ַ�������
    void Init(); // ��ʼ��
    void UnInit(); // �ͷ���Դ
    int MyStrLen(const char * pszString) const; // 
    char *  MyStrCpy(char * pszDest, const char * pszSour); // 
    int IndistinctSearch(const char *pszToSearch, int nStart = 0) const; // ָ��λ�ò����ַ�����Ĭ�Ͽ�ʼ�±�0
    int WholeWordSearch(const char *SearchStr, int nStart = 0) const;//ȫ��ƥ���ѯ��Ĭ�Ͽ�ʼ�±�0
};
