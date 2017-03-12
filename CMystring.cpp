
#include "stdafx.h"
#include "CMystring.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CMyString::CMyString()
{
    Init();
}

CMyString::CMyString(const char *pszString)
{
    Init();
    SetString(pszString);
}

CMyString::CMyString(const CMyString &obj)
{
    SetString(obj.GetString());
}

CMyString::~CMyString()
{
    UnInit();
}

int CMyString::MyStrLen(const char * pszString) const
{
    int nCount = 0, i = 0;
    for (; *(pszString + i) != '\0'; i++)
    {
        nCount++;
    }
    return nCount;
}

char * CMyString::MyStrCpy(char * pszDest, const char * pszSour)
{
    int i = 0;
    for ( ; *(pszSour + i) != '\0'; i++)
    {
        *(pszDest + i) = *(pszSour + i);
    }
    pszDest[i] = '\0';
    return pszDest;
}

/*************************************************************************
function: return the string witch save in the buff
parameter: none
return: the string in buff
remark: none
/************************************************************************/
char *CMyString::GetString() const 
{
    return m_pszBuff;
}

/*************************************************************************
function: init the buff = 0, buffsize = 0, strlen = 0
parameter: none
return: none
remark: none
/************************************************************************/
void CMyString::Init()
{
    m_pszBuff = NULL;
    m_nLength = 0;
    m_nBuffSize = 0;
}

/*************************************************************************
function: Unint BuffInfo and release apply space 
parameter: none
return: none
remark: none
/************************************************************************/
void CMyString::UnInit()
{
    if(m_pszBuff != NULL)
    {
        delete[] m_pszBuff;
        m_pszBuff = NULL;
        m_nLength = 0;
        m_nBuffSize = 0;
    }
}

/*************************************************************************
function: copy pszString into buff
parameter: pszString[NewString]
return: note
remark: return true if success,other false
/************************************************************************/
bool CMyString::SetString(const char *pszString)
{
    int nNeedLen = MyStrLen(pszString) + sizeof(char);
    if (nNeedLen > m_nBuffSize) // ���ԭ���Ŀռ䲻�����
    {
        UnInit(); // �ͷ�ԭ���Ŀռ�
        // ��������ռ�
        m_pszBuff = new char[nNeedLen];
        if (m_pszBuff == NULL)
        {   // �������ʧ���򷵻�
            return false;
        }
        m_nBuffSize = nNeedLen; // ����buff����
    }
    MyStrCpy(m_pszBuff, pszString); // �����ַ���
    m_nLength = nNeedLen - 1; // �ַ������ȵ�buff����-1
    return true;
}

/*************************************************************************
function: get apply space size
parameter: none
return: the size of buff
remark: none
/************************************************************************/
int CMyString::GetBuffSize() const
{
    return m_nBuffSize;
}

/*************************************************************************
function: get the length of string who is saved in buff
parameter: none
return: length of string
remark: none
/************************************************************************/
int CMyString::GetLength() const
{
    return m_nLength;
}

/*************************************************************************
function: split joint chars to the end of string
parameter: const char *pszString
return: true if success, false for fail
remark: none
/************************************************************************/
bool CMyString::StrCat(const char *pszString)
{
    // ��Ҫ��BUFF�ܳ���= ԭ����+Ҫƴ�ӵĳ���
    int nNeedLen = MyStrLen(pszString) + MyStrLen(m_pszBuff) + sizeof(char);
    //���buff���Ȳ����ڴ��
    if (nNeedLen > m_nBuffSize)
    {   // ������һ���㹻��Ŀռ�
        char *pOllStr = new char[nNeedLen];
        if (m_pszBuff == NULL)
        {
            return false;
        }
        MyStrCpy(pOllStr, m_pszBuff); 
        UnInit();
        m_pszBuff = pOllStr;
        m_nBuffSize = nNeedLen;
    }
    MyStrCpy(&m_pszBuff[MyStrLen(m_pszBuff)], pszString);
    m_nLength = nNeedLen - 1;
    return true;
}

/*************************************************************************
function: split joint CMyString &obj string to the end of string
parameter: const CMyString &str
return: success return true,other false
remark: none
/************************************************************************/
bool CMyString::StrCat(const CMyString &str)
{
    if(StrCat(str.GetString()))
    {
        return true;
    }
    else
    {
        return false;
    }
}

/*************************************************************************
function: split joint char to the end of string
parameter: const char ch
return: success return true, other false
remark: none
/************************************************************************/
bool CMyString::StrCat(const char ch)
{
    char ch1[2] = {0};
    ch1[1] = '\0';
    ch1[0] = ch;
    if(StrCat(ch1))
    {
        return true;
    }
    else
    {
        return false;
    }
}

/*************************************************************************
function: make sure string empty or not
parameter: none
return: empty return true, other false
remark: none
/************************************************************************/
bool CMyString::IsEmpty() const
{
    return (m_nLength==0)?true:false;
}

/*************************************************************************
function: return the buff address
parameter: none
return: buff address with unsigned int
remark: none
/************************************************************************/
unsigned int CMyString::GetBuff() const // ����buff��ַ
{
    return (unsigned int)m_pszBuff;
}

/*************************************************************************
function: convert lower-case to capital
parameter: none
return: none
remark: none
/************************************************************************/
void CMyString::MakeUpper() // Сдת��д
{
    int ntmp = 0;
    for (; ntmp < m_nLength; ntmp++)
    {
        if (m_pszBuff[ntmp] >= 'a' && m_pszBuff[ntmp] <= 'z')
        {
            m_pszBuff[ntmp] -= 'a' - 'A';
        }
    }
}

/*************************************************************************
function: convert capital to lower-case
parameter: none
return: none
remark: none
/************************************************************************/
void CMyString::MakeLower() // ��дתСд
{
    int ntmp = 0;
    for (; ntmp < m_nLength; ntmp++)
    {
        if (m_pszBuff[ntmp] >= 'A' && m_pszBuff[ntmp] <= 'Z')
        {
            m_pszBuff[ntmp] += 'a' - 'A';
        }
    }
}

/*************************************************************************
function: reverse string
parameter: none
return: none
remark: none
/************************************************************************/
void CMyString::MakeReverse() // ��ת�ַ���
{
    char chTmp = '\0';
    int itmp = 0;
    int nCount = m_nLength / 2;
    for (; itmp < nCount; itmp++)
    {
        chTmp = *(m_pszBuff + itmp);
        *(m_pszBuff + itmp) = *(m_pszBuff + m_nLength - 1 - itmp);
        *(m_pszBuff + m_nLength - 1 - itmp) = chTmp;
    }   
}

/*************************************************************************
function: replace old char to new char
parameter: 
            chOld:you want to bereplace,
            chNew:witch one you want to replase 
return: success return true, other return false
remark: none
/************************************************************************/
bool CMyString::Replace(const char chOld, const char chNew)
{
    char szOld[2] = {0};
    szOld[1] = '\0';
    szOld[0] = chOld;

    char szNew[2] = {0};
    szNew[1] = '\0';
    szNew[0] = chNew;

    if( Replace(szOld, szNew))
    {
        return true;
    }
    else
    {
        return false;
    }
}

/*************************************************************************
function: replace old chars for new chars
parameter: 
pszOld: old string you want to be replace
pszNew: New string you want to replace
return: success if true, other return false
remark: none
/************************************************************************/
bool CMyString::Replace(const char *pszOld, const char *pszNew) // �����ַ����滻���ַ���
{
    int nIndex = 0;
    int npszNewLen = MyStrLen(pszNew);
    int npszOldLen = MyStrLen(pszOld);
    for (; *(m_pszBuff + nIndex) != '\0'; nIndex++)
    {
        nIndex = IndistinctSearch(pszOld, nIndex); // ��IndistinctSearch����Ҫ�޸ĵ��ַ������±�
        if (nIndex == -1) // search����-1��ʾ�ִ�����û�а�����Ҫ�޸ĵ��ַ���
        {
            return false;
        }
        if (npszNewLen == npszOldLen) // ���ԭ����������ĳ�����ͬ
        {   // �����ֱ�Ӵ��������Ҳ����޸�ԭ���ĳ���
            for (int itmp = 0; *(pszNew + itmp) != '\0'; itmp++)
            {
                *(m_pszBuff + nIndex - 1 + itmp) = *(pszNew + itmp);
            }
            nIndex--;
        }
        // ���򣬾͵ð�ƥ���ַ�����ı��������������´��������ӻؾɴ������޸Ĵ�����
        // ����ע��ԭ���Ƿ��㹻�ռ���
        else if (npszOldLen >= npszNewLen)
        {    // �ɴ��㹻��ţ������������Ŀռ䣬�޸����Ҫ���ַ�����ԭ��СΪʵ�ʴ�С
            char *pNewBuff = new char[MyStrLen(&m_pszBuff[nIndex])]; // ��index������ִ����Ƴ�ȥ
            if (pNewBuff == NULL)
            {
                return false;
            }
            MyStrCpy(&m_pszBuff[nIndex], pszNew); // �´����ƽ�ȥ
            MyStrCpy(&m_pszBuff[MyStrLen(m_pszBuff)], pszNew);  // ��index������ִ����ƻ�ȥ
            m_nLength += npszOldLen - npszNewLen; // �޸ĳ���
            if (pNewBuff != NULL) // �ͷ�����Ŀռ�
            {
                delete[] pNewBuff;
                pNewBuff = NULL;
            }
        }
        else // ��Ȼ���ǿռ䲻��
        {    // ��Ҫ�������ĺ��ʵĿռ�
            int nNeedLen = MyStrLen(m_pszBuff) + npszNewLen - npszOldLen + sizeof(char);
            char *pszNewBuff = new char[nNeedLen];
            if (pszNewBuff == NULL)
            {
                return false;
            }
            MyStrCpy(pszNewBuff, m_pszBuff); // ���ɴ�ȫ�����ƽ�ȥ
            MyStrCpy(&pszNewBuff[nIndex - 1], pszNew); //�´���nindexλ�ô����ɴ�
            // ���Ƴ����ľɴ��ӱ�������λ�ÿ�ʼ���Ƶ��´�
            MyStrCpy(&pszNewBuff[MyStrLen(pszNewBuff)], &m_pszBuff[nIndex + npszOldLen - 1]); 
            m_nBuffSize = nNeedLen; //����BUFF��С
            m_nLength = nNeedLen - 1; // ���´���С
            if (m_pszBuff != NULL) //�ͷž�buff�ռ�
            {
                delete[] m_pszBuff;
            }
            m_pszBuff = pszNewBuff; //����buff��ַ
        }
    }
    return true;
}

/*************************************************************************
function: return the last match sub char in string
parameter: chToFind: char you want to be found
return: return -1 if not match, other return index
remark: none
/************************************************************************/
int CMyString::ReverseFind(const char chToFind) const// ���ҷ������ƥ����ַ��±�(�����Ķ�)
{
    char szStr[2] = {0};
    szStr[1] = '\0';
    szStr[0] = chToFind;

    int nIndex = -1, itmp = -1;
    for (; *(m_pszBuff + itmp) != '\0'; itmp++)
    {
        nIndex = WholeWordSearch(szStr);
        if (nIndex != -1)
        {
            itmp = nIndex;
        } 
    }
    return itmp;
}

/*************************************************************************
function: Remove all match with chRemove
parameter: chRemove: the char you want to delete
return: nCount:how many char have been delete
remark: none
/************************************************************************/
int CMyString::Remove(const char chRemove) // ���ַ�����ɾ�����е�ָ�����ַ�
{
    int itmp, jtmp, nCount = 0;
    // ѭ�������׸����ϵ�ɾ���ַ�
    for (itmp = 0; itmp < m_nLength; itmp++)
    {
        if (*(m_pszBuff + itmp) == chRemove)
        {   // �ҵ��׸�����׶ζ����Һ����׸�����Ҫɾ�����ַ�
            for (jtmp = itmp + 1; jtmp < m_nLength; jtmp++)
            {   
                if (*(m_pszBuff + jtmp) != chRemove)
                {   // ����Ҫɾ�����ַ��ҵ����ƴ�ӵ�ɾ���ַ�λ��
                    *(m_pszBuff + itmp++) = *(m_pszBuff + jtmp);
                    nCount++;
                }
            }
            break;
        }
    }
    m_nLength = itmp;
    m_pszBuff[itmp] = '\0';
    return nCount;
}

/*************************************************************************
function: insert char into the Index of string
parameter: nIndex:the index you want to insert, chInsert:insert char
return: 
remark: none
/************************************************************************/
bool CMyString::Insert(int nIndex, const char chInsert) // ָ��λ�ò��뵥���ַ�
{
    char ch[2] = {0};
    ch[1] = '\0';
    ch[0] = chInsert;
    if (nIndex > m_nLength)
    {
        nIndex = m_nLength + 1;
    }
    if( Insert(nIndex, ch) )
    {
        return true;
    }
    else
    {
        return false;
    }
    
}

/*************************************************************************
function: insert string to the index of string
parameter: 
nIndex:the nidex you want to insert,
szInsert: the string you want to insert
return: success return true, else return false
remark: none
/************************************************************************/
bool CMyString::Insert(int nIndex, const char *szInsert) // ָ��λ�ò����ַ���
{
    // �ж�buff�����Ƿ���
    int nNeedLen = MyStrLen(szInsert) + m_nLength + sizeof(char);
    if (nNeedLen > m_nBuffSize)
    {
        // ���빻�õĳ���
        char *pNew = new char[nNeedLen];
        if (pNew == NULL)
        {
            return false;
        }
        MyStrCpy(pNew, m_pszBuff); // �Ѿɴ����Ƶ��´�
        MyStrCpy(&pNew[nIndex - 1], szInsert); // �´���nIndex��ʼ����Ҫ����Ĵ�
        MyStrCpy(&pNew[MyStrLen(pNew)], &m_pszBuff[nIndex - 1]); // ���ں��渴��ʣ�µľɴ�
        UnInit();
        m_nLength = nNeedLen - 1;
        m_nBuffSize = nNeedLen;
        m_pszBuff = pNew;
    }
    else // ���õĻ�
    {
        char * pNew= new char[MyStrLen(&m_pszBuff[nIndex - 1]) + sizeof(char)];
        if (pNew == NULL)
        {
            return false;
        }
        MyStrCpy(pNew, &m_pszBuff[nIndex - 1]); // �Ѿɴ�ƴ��λ�ú���ַ������Ƶ��´�
        MyStrCpy(&m_pszBuff[nIndex - 1], szInsert); // ���´����Ƶ�ƴ�ӵ�ַ
        MyStrCpy(&m_pszBuff[MyStrLen(m_pszBuff)], pNew); // ��ԭ�ɴ�ƴ��λ�ú���ַ������ƻ�ȥ
        if (pNew != NULL) // �ͷ�����Ŀռ�
        {
            delete[] pNew;
            pNew = NULL;
        }
        m_nLength = m_nLength + MyStrLen(szInsert);
    }
    return true;
}

/*************************************************************************
function: delete chars from nIndex,  default nCount 1
parameter: nIndex:begin location to delete, nCount:how many you want to delete
return: how many been delete
remark: none
/************************************************************************/
int CMyString::Delete(int nIndex, int nCount) // ɾ��ָ��λ���𣬹�count���ַ���Ĭ��1���ַ�
{
    MyStrCpy(&m_pszBuff[nIndex - 1], &m_pszBuff[nIndex - 1 + nCount]);
    m_nLength -= nCount;
    return nCount;
}

/*************************************************************************
function: found char location in a string,
parameter: chToFind[char you want to found]
return: if not exist,return -1, else return index
remark: none
/************************************************************************/
int CMyString::Find(const char chToFind)  const
{
    char szch[2];
    szch[1] = '\0';
    szch[0] = chToFind;
    return IndistinctSearch(szch);
}

/*************************************************************************
function: found chars location in a string,
parameter: pszToFind[chars you want to found]
return: if not exist,return -1, else return index
remark: none
/************************************************************************/
int CMyString::Find(const char* pszToFind) const
{
    return IndistinctSearch(pszToFind);
}

/*************************************************************************
function: found char begin with specify index location in a string,
parameter: chToFind[char you want to found]
return: if not exist,return -1, else return index
remark: none
/************************************************************************/
int CMyString::Find(const char chToFind, int nStart) const
{
    char szch[2];
    szch[1] = '\0';
    szch[0] = chToFind;
    return IndistinctSearch(szch, nStart);
}

/*************************************************************************
function: found chars begin with specify index location in a string,
parameter: pszToFind[char you want to found]
return: if not exist,return -1, else return index
remark: none
/************************************************************************/
int CMyString::Find(const char* pszToFind, int nStart) const
{
    return IndistinctSearch(pszToFind, nStart);
}

/*
ָ��λ�ò����ַ�����Ĭ�Ͽ�ʼ�±�0
�ҵ��򷵻ص��������е��±�
Ҳ�����ڴ�ƫ��+1�����򷵻�-1
*/
/*************************************************************************
function: found chars with specify begin index location in a string,
parameter: pszToSearch[char you want to found], nStart default = 0
return: if not exist,return -1, else return index
remark: none
/************************************************************************/
int CMyString::IndistinctSearch(const char *pszToSearch, int nStart) const
{
    int i = 0, j = 0;
    char *p = m_pszBuff;
    p += nStart;
    for (j = 0; *p != '\0'; p++)
    {
        j++;
        if( *p == *pszToSearch)
        {
            for (i = 0; *(pszToSearch + i) != '\0'; i++, p++)
            {
                if (*(pszToSearch + i) != *p)
                {
                    break;
                }
            }
            if(*(pszToSearch + i) == '\0')
            {
                return j + nStart;
            }
        }
    }
    return -1;
}

int CMyString::WholeWordSearch(const char *SearchStr, int nStart) const//ȫ��ƥ���ѯ
{
    char *p = m_pszBuff;
    p += nStart;
    int nIndex = 0;
    for (; *SearchStr != '\0'; SearchStr++, p++)
    {
        nIndex++;
        if (*SearchStr != *p)
        {
            return -1;
        }
    }
    if (*SearchStr == '\0' && *p == '\0')
    {
        return nIndex;
    }
    else
    {
        return -1;
    }
}

CMyString::operator char*()
{
	return m_pszBuff;
}