#include "StdAfx.h"
#include "MyDexObj.h"

#define LEB128MAXBYTESIZE 5

uint32_t g_AccessFlags[] = {
    kAccPublic,
		kAccPrivate,
		kAccProtected,
		kAccStatic,
		kAccFinal,
		kAccSynchronized,
		kAccSuper,
		kAccVolatile,
		kAccBridge,
		kAccTransient,
		kAccVarargs,
		kAccNative,
		kAccInterface,
		kAccAbstract,
		kAccStrict,
		kAccSynthetic,
		kAccAnnotation,
		kAccEnum,
		kAccMiranda,
		//kAccJavaFlagsMask,
		kAccConstructor,
		kAccDeclaredSynchronized,
		kAccClassIsProxy,
		kAccPreverified,
		kAccClassIsFinalizable,
		kAccClassIsReference,
		kAccClassIsWeakReference,
		kAccClassIsFinalizerReference,
		kAccClassIsPhantomReference,
};

///////////////////////////////////////////////////////////////////////////
/* 函数功能：返回LEB128占用大小
 * 函数参数: LEB128指针
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint getLeb128Size(BYTE *pByte)
{
    uint nLen = 1;
    //一个循环，以LEB128最长的5个字节为界限
    for(uint i = 0; i < LEB128MAXBYTESIZE; i++, pByte++)
    {
        //读取BYTE取符号位判断是否为1
        BYTE by = *pByte;
        //如果此时的符号位为0则LEB扩展结束
        if ((by & 0x80) == 0)
        {
            return nLen + i;
        }
    }
    return 0;
}

///////////////////////////////////////////////////////////////////////////
/* 函数功能：读取LEB128存储的实际表示内容
 * 函数参数: LEB128指针
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint readLeb128(BYTE *pByte)
{
    uint nRet = 0;
    uint nCur = 0;
    //一个循环，以LEB128最长的5个字节为界限
    for(uint i = 0; i < LEB128MAXBYTESIZE; i++, pByte++)
    {
        //读取BYTE取符号位判断是否为1
        BYTE by = *pByte;
        //无论如何，先作累加
        nCur = by & 0x7f;
        nRet = nRet + (nCur << (7 * i));
        //如果此时的符号位为0则LEB扩展结束
        if ((by & 0x80) == 0)
        {
            break;
        }
    }
    return nRet;
}

CMyDexObj::CMyDexObj() : m_pNew(NULL), m_pHeader(NULL), m_pMapInfo(NULL)
{
#ifdef DEBUGLOG
    printf("CMyDexObj::CMyDexObj()\r\n");
#endif
    m_nStringIdItemSize = 0;                //StringIdItem个数
    m_pStringItem = NULL;                   //StringIdItem指针
    
    m_nTypeIdItemSize = 0;                  //TypeIdItem个数
    m_pTypeIdItem = NULL;                   //TypeIdItem指针
    
    m_nProtoIdItemSize = 0;                 //ProtoIdItem个数
    m_pProtoIdItem = NULL;                  //ProtoIdItem指针

    m_nFieldIdItemSize = 0;                 //FieldIdItem个数
    m_pFieldIdItem = NULL;                  //FieldIdItem指针
    
    m_nMethodIdItemSize = 0;                //MethodIdItem个数
    m_pMethodIdItem = NULL;                 //MethodIdItem指针    
    
    m_nClassDefItemSize =0;                  //ClassDefItem个数
    m_pClassDefItem = NULL;                   //ClassDefItem指针
}
bool CMyDexObj::isDexFile()
{
    ASSERT(m_pHeader != NULL);

    return true;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：判断DEX文件合法性并负责初始化各个必要字段
 * 函数参数: 读取的文件内容首地址
 * 函数返回值：true正常初始化，false出问题
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::init(void *pContext)
{
    m_pNew = pContext;
    m_pHeader = (STHeader*)pContext;
    //如果判断不是合法dex文件则退出
    if(!isDexFile())
        return false;
    //指向map_list_type(其实是MapInfo)结构的地址=头文件地址+map_off的偏移
    m_pMapInfo = (STMapInfo *)(m_pHeader->map_off_ + getFileBeginAddr());
    //取出map_list个数保存
    m_nMapItemSize = m_pMapInfo->m_nSize;
    //取出MapItem的地址保存
    m_pMapItem = (STMapItem *)(m_pMapInfo->m_MapItem);

    //获取字符串信息必要参数，获取字符串信息
    initStringItemInfo();
    //获取type_id_item必要参数
    initTypeIdItemST();
    //获取proto_id_item必要参数
    initProtoIdItemST();
    //获取field_id_item必要参数
    initFieldIdItemST();
    //获取method_id_item必要参数
    initMethodIdItemST();
    //获取classdef_item必要参数
    initClassDefItemST();
    return true;
}
//获取Magic
char* CMyDexObj::getMagic()               
{
    return (char*)&m_pHeader->magic_[0];
}

CMyDexObj::~CMyDexObj()
{
#ifdef DEBUGLOG
    printf("CMyDexObj::~CMyDexObj()\r\n");
#endif
}
DWORD CMyDexObj::getFileBeginAddr()       //获取文件在内存的首地址
{
    return (DWORD)m_pHeader;
}
//获取文件校验码
uint32_t CMyDexObj::getChecksum()         
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->checksum_;
}
//获取签名信息
BYTE* CMyDexObj::getSignature()           
{
    ASSERT(m_pHeader != NULL);
    return &m_pHeader->signature_[0];
}
//获取header结构中指示的文件大小
uint32_t CMyDexObj::getFileSize()         
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->file_size_;
}
//获取HEADER结构大小
uint32_t CMyDexObj::getHeaderSize()       
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->header_size_;
}
//获取大小尾标志
uint32_t CMyDexObj::getEndianTag()        
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->endian_tag_;
}
// unused
uint32_t CMyDexObj::getLinkSize()         
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->link_size_;
}
// unused
uint32_t CMyDexObj::getLinkOff()
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->link_off_;
}
// unused
uint32_t CMyDexObj::getMapOff()
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->map_off_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：返回Header结构中的StringIdsSize
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getStringIdsSize()    
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->string_ids_size_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：返回Header结构中的StringIds文件偏移
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getStringIdsOff()     // file offset of StringIds array
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->string_ids_off_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getTypeIdsSize()      // number of TypeIds, we don't support more than 65535
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->type_ids_size_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getTypeIdsOff()       // file offset of TypeIds array
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->type_ids_off_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getProtoIdsSize()     // number of ProtoIds, we don't support more than 65535
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->proto_ids_size_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getProtoIdsOff()      // file offset of ProtoIds array
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->proto_ids_off_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getFieldIdsSize()     // number of FieldIds
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->field_ids_size_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getFieldIdsOff()      // file offset of FieldIds array
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->field_ids_off_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getMethodIdsSize()    // number of MethodIds
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->method_ids_size_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getMethodIdsOff()     // file offset of MethodIds array
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->method_ids_off_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassDefsSize()    // number of ClassDefs
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->class_defs_size_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassDefsOff()     // file offset of ClassDef array
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->class_defs_off_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getDataSize()         // unused
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->data_size_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getDataOff()          // unused
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->data_off_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const STMapInfo* CMyDexObj::getMapInfo()  //拿map_list结构起始地址
{
    ASSERT(m_pMapInfo != NULL);
    return m_pMapInfo;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：遍历对应MapItem返回指定类型结构的指针
 * 函数参数: 目录Item类型
 * 函数返回值：存在返回对应指针，否则返回-1
 */
///////////////////////////////////////////////////////////////////////////
STMapItem * CMyDexObj::getMapItemWithType(EMMapItemType type)
{
    for (uint i = 0; i < getMapItemSize(); i++)
    {
        if (m_pMapItem[i].type_ == type)
        {
            return &m_pMapItem[i];
        }
    }
    return (STMapItem *)EERROR;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取MapItem个数
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint CMyDexObj::getMapItemSize()     
{
    return m_nMapItemSize;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：初始化StringItem相关数据 
                m_pStringItem           //StringItem地址
                m_nStringIdItemSize     //String个数
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::initStringItemInfo() 
{
    //遍历MapItem是否存在对应类型结构数据
    STMapItem *pST = (STMapItem *)getMapItemWithType(kDexTypeStringIdItem);
    //如果存在
    if((DWORD)pST != EERROR)
    {
        //保存指向StringItem的指针=MapItem结构指向的偏移+文件头地址
        m_pStringItem = (STStringIdItem*)((DWORD)pST->offset_ + getFileBeginAddr());
        //保存StringItem个数
        m_nStringIdItemSize = pST->size_;
        //ColletionStringIdItem();
    }
    return (DWORD)m_pStringItem != EERROR;
}

///////////////////////////////////////////////////////////////////////////
/* 函数功能：初始化TypeIdItem相关数据 
                m_pTypeIdItem           //TypeIdItem地址
                m_nTypeIdItemSize       //TypeIdItem个数
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::initTypeIdItemST()      //初始化type_id_item必要结构
{
    //遍历MapItem是否存在对应类型结构数据
    STMapItem *pST = (STMapItem *)getMapItemWithType(kDexTypeTypeIdItem);
    //如果存在
    if((DWORD)pST != EERROR)
    {
        //保存指向TypeIdItem的指针=MapItem结构指向的偏移+文件头地址
        m_pTypeIdItem = (STTypeIdItem*)((DWORD)pST->offset_ + getFileBeginAddr());
        //保存TypeItItem个数
        m_nTypeIdItemSize = pST->size_;
        //ColletionTypeIdItem();
    }
    return (DWORD)m_pTypeIdItem != EERROR;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取MapItem结构中StringItem个数
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getStringItemSize()
{
    return m_nStringIdItemSize;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿string_id_list指定下标的字符串
 * 函数参数: 下标
 * 函数返回值：
*/
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getStringIdStringFromId(uint nIndex)
{
    ASSERT(nIndex < m_nStringIdItemSize && nIndex >= 0);
    //字符串数据首地址
    BYTE *pLeb128 = getStringIdItemAddrFromId(nIndex);
    //item首地址为leb128类型数据来指示这个ITEM中的字符串的长度
    return (char *)((DWORD)pLeb128 + getLeb128Size(pLeb128));
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿指定下标的StringItem首地址
 * 函数参数: 下标
 * 函数返回值：
*/
///////////////////////////////////////////////////////////////////////////
BYTE *CMyDexObj::getStringIdItemAddrFromId(uint nIndex)
{
    ASSERT(nIndex < m_nStringIdItemSize && nIndex >= 0);
    return (BYTE*)(getFileBeginAddr() + (DWORD)m_pStringItem[nIndex].m_nOffset);
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿指定下标字符串的长度
 * 函数参数: 下标
 * 函数返回值：
*/
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getStringLenFromIndex(uint nIndex)
{
    ASSERT(nIndex < m_nStringIdItemSize && nIndex >= 0);
    BYTE *pByte = getStringIdItemAddrFromId(nIndex);

    return readLeb128(pByte);
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿指定下标字符串的长度
 * 函数参数: 下标
 * 函数返回值：
*/
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getStringFillOffFromIndex(uint nIndex) //拿指定下标字符串的文件偏移
{
    ASSERT(nIndex < m_nStringIdItemSize && nIndex >= 0);
    return m_pStringItem[nIndex].m_nOffset;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿type_id_list指定下标的字符串
 * 函数参数: 下标
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getTypeIdStringFromId(uint nIndex)
{
    //调用getStringFromId接口，m_pTypeIdItem[nIndex].descriptor_idx_拿对应下标
    ASSERT(nIndex < m_nTypeIdItemSize && nIndex >= 0);
    return getStringIdStringFromId(m_pTypeIdItem[nIndex].descriptor_idx_);
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取type_id_item数量
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getTypeItemSize()
{
    return m_nTypeIdItemSize;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：收集字符串表
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::ColletionStringIdItem()
{
    for (DWORD i = 0; i < m_nStringIdItemSize; i++)
    {
        //http://androidxref.com/4.4.4_r1/xref/cts/tools/dex-tools/src/dex/reader/DexBuffer.java
        //字符串数据首地址
        //BYTE *pLeb128 = (BYTE*)(getFileBeginAddr() + (DWORD)m_pStringItem[i].m_nOffset);
//         BYTE *pLeb128 = getStringIdItemAddrFromId(i);
//         printf("%d pStrLen[%X]-> %x ==>%s\r\n", i, 
//             readLeb128(pLeb128), //LEB实际数据大小
//             m_pStringItem[i].m_nOffset, //文件偏移
//             (DWORD)pLeb128 + getLeb128Size(pLeb128));

        printf("%d pStrLen[%X]-> %x ==>%s\r\n", i, 
            getStringLenFromIndex(i), //LEB实际数据大小
            getStringFillOffFromIndex(i), //文件偏移
            getStringIdStringFromId(i));
    }
    return true;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：收集type_id_item表（类型表）
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::ColletionTypeIdItem()
{
    //循环遍历
    for (DWORD i = 0; i < getStringItemSize(); i++)
    {
        //调用getTypeIdStringFromId接口，下标
        printf("%d ==>%s\r\n", i, getTypeIdStringFromId(i));        
    }
    return true;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：初始化proto_id_item必要结构
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::initProtoIdItemST()
{
    //遍历MapItem是否存在对应类型结构数据
    STMapItem *pST = (STMapItem *)getMapItemWithType(kDexTypeProtoIdItem);
    //如果存在
    if((DWORD)pST != EERROR)
    {
        //保存指向ProtoIdItem的指针=MapItem结构指向的偏移+文件头地址
        m_pProtoIdItem = (STProtoIdItem*)((DWORD)pST->offset_ + getFileBeginAddr());
        //保存ProtoIdItem个数
        m_nProtoIdItemSize = pST->size_;
        //ColletionProtoIdItem();
    }
    return (DWORD)m_pProtoIdItem != EERROR;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：收集proto_id_item表
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::ColletionProtoIdItem()
{
    STProtoIdItem *pST = NULL;
    for (DWORD i = 0; i < m_nProtoIdItemSize; i++)
    {
        //获取该下标类型的地址
        pST = getProtoIdSTFromId(i);
        ASSERT(pST != NULL);
#ifdef DEBUGLOG
        //输出相关结构数据
        printf("[%d]: shorty_idx: %X return_type_idx: %X parameters_off: %X\r\n",
            i, pST->shorty_idx_, pST->return_type_idx_, pST->parameters_off_);
#endif 
        printf("[%d]: shorty_idx: %s return_type_idx: %s ",
            i, getStringIdStringFromId(pST->shorty_idx_), 
            getTypeIdStringFromId(pST->return_type_idx_));//
        const char* pstr = getParametersStringFromIndex(i);
        printf("%s\r\n", pstr);
        delete[] (char*)pstr;
        pstr = getProtoIdStringFromId(i);
        printf("\tProtoIdString: %s\r\n", pstr);
        delete[] (char*)pstr;
    }
    return true;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿指定下标方法的极简返回值跟参数字符串
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getShortyIdxStringFromIndex(uint nIndex)
{
    //这个ShortyIdx字段实际是指向StringId字符串表的下标，调用返回即可
    return getStringIdStringFromId(getShortyIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿指定下标方法的返回类型字符串
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getReturnTypeIdxStringFromIndex(uint nIndex)
{
    //这个return_type_idx_字段实际是指向TypeId字符串表的下标，调用返回即可
    return getTypeIdStringFromId(getReturnTypeIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿指定下标方法的参数列表字符串
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getParametersStringFromIndex(uint nIndex)
{
    char temp[MAXBYTE];
    char *tempret = new char[MAXBYTE * 4];
    tempret[0] = '\0';
    //拿参数字段偏移
    DWORD dwOff = getParametersOffFromIndex(nIndex);
    //没有参数时该off为0 
    if (dwOff != 0)
    {
        PSTTypeList pTL = (STTypeList*)(dwOff + getFileBeginAddr());
        sprintf(temp, "parameters_off[%d]: ", pTL->size_);
        strcpy(tempret, temp);
		//循环加入所有参数
        for (uint j = 0; j < pTL->size_; j++)
        {
            sprintf(temp, "%s ", getTypeIdStringFromId(pTL->list_[j].type_idx_));
            strcat(tempret, temp);
        }
    }
    else
    {
        sprintf(temp, "parameters_off[%d]: 0", 0);
        return strcpy(tempret, temp);
    }
    return tempret;
}

DWORD CMyDexObj::getShortyIdxValueFromIndex(uint nIndex) //拿指定下标方法的ShortyIdx字段值
{
    //取出proto结构下标数据
    STProtoIdItem *pST = NULL;
    pST = getProtoIdSTFromId(nIndex);
    return pST->shorty_idx_;
}
DWORD CMyDexObj::getReturnTypeIdxValueFromIndex(uint nIndex) //拿指定下标方法的ReturnTypeIdx字段值 
{
    //取出proto结构下标数据
    STProtoIdItem *pST = NULL;
    pST = getProtoIdSTFromId(nIndex);
    return pST->return_type_idx_;
}
DWORD CMyDexObj::getParametersValueFromIndex(uint nIndex) //拿指定下标方法的Parameter字段值
{
    //取出proto结构下标数据
    STProtoIdItem *pST = NULL;
    pST = getProtoIdSTFromId(nIndex);
    return pST->parameters_off_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿proto_id_list指定下标的结构首地址
 * 函数参数: nIndex要获取的下标
 * 函数返回值：该下标的结构体指针
 */
///////////////////////////////////////////////////////////////////////////
STProtoIdItem* CMyDexObj::getProtoIdSTFromId(uint nIndex)
{
    ASSERT(m_pProtoIdItem != NULL);
    ASSERT(m_nProtoIdItemSize > nIndex && nIndex >= 0);
    return &m_pProtoIdItem[nIndex];
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取指定下标方法的参数列表字段值
 * 函数参数: nIndex要获取的下标
 * 函数返回值：参数列表字段值
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getParametersOffFromIndex(uint nIndex)
{
    STProtoIdItem* pST = getProtoIdSTFromId(nIndex);
    if(pST != NULL)
    {
        return pST->parameters_off_;
    }
    return 0;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取指定下标方法的TypeList结构地址（实际内存地址）
 * 函数参数: nIndex要获取的下标
 * 函数返回值：该下标的结构体指针
 */
///////////////////////////////////////////////////////////////////////////
STTypeList *CMyDexObj::getTypeList(uint nIndex)
{
    DWORD dwParametersOff = getParametersOffFromIndex(nIndex);
    //参数列表不为空才读取返回
    if(dwParametersOff != 0)
    {
        //循环输出参数
        STTypeList *pTL = (STTypeList *)(dwParametersOff + getFileBeginAddr());
        return pTL;
    }
    return NULL;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿proto_id_list数组指定下标的函数原型信息,返回值需要手动释放
 * 函数参数: nIndex要获取的下标
 * 函数返回值：该下标的结构体指针
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getProtoIdStringFromId(uint nIndex)
{
    char temp[MAXBYTE];
    char *Tempret = new char[MAXBYTE *4];
    Tempret[0] = '\0';
    STProtoIdItem* pST = getProtoIdSTFromId(nIndex);
    if(pST != NULL)
    {
        //返回值（参数列表）
        sprintf(Tempret, "%s (", getTypeIdStringFromId(pST->return_type_idx_));
        DWORD dwOff = getParametersOffFromIndex(nIndex);
        //参数列表不为空才需要输出 
        if(dwOff)
        {
            //循环输出参数
            STTypeList *pTL = (STTypeList *)(dwOff + getFileBeginAddr());
            for (DWORD i = 0; i < pTL->size_; i++)
            {
                sprintf(temp, " %s", getTypeIdStringFromId(pTL->list_[i].type_idx_));
                strcat(Tempret, temp);
            }
        }
        else
            strcat(Tempret ,"void");
        strcat(Tempret, ")");
    }
    return Tempret;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：初始化field_id_item必要结构
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::initFieldIdItemST()
{
    //遍历MapItem是否存在对应类型结构数据
    STMapItem *pST = (STMapItem *)getMapItemWithType(kDexTypeFieldIdItem);
    //如果存在
    if((DWORD)pST != EERROR)
    {
        //保存指向FieldIdItem的指针=MapItem结构指向的偏移+文件头地址
        m_pFieldIdItem = (STFieldIdItem*)((DWORD)pST->offset_ + getFileBeginAddr());
        //保存ProtoIdItem个数
        m_nFieldIdItemSize = pST->size_;
        //ColletionFieldIdItem();
    }
    return (DWORD)m_pFieldIdItem != EERROR;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：收集field_id_item表
 * 函数参数: nIndex要获取的下标
 * 函数返回值：该下标的结构体指针
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::ColletionFieldIdItem()
{
    STFieldIdItem *pST = NULL;
    for (DWORD i = 0; i < getFieldIdSizeFromSave(); i++)
    {
        //获取该下标类型的地址
        pST = getFieldIdSTFromId(i);
        ASSERT(pST != NULL);
#ifdef DEBUGLOG
        //输出相关结构数据
        printf("[%d]: class_idx: %X type_idx: %X name_idx: %X\r\n",
            i, pST->class_idx_, pST->type_idx_, pST->name_idx_);
#endif 
        printf("[%d]: class_idx: %s type_idx: %s name_idx: %s\r\n",
            i, 
            getTypeIdStringFromId(getClassIdxValueFromId(i)), 
            getTypeIdStringFromId(getProtoIdxValueFromId(i)), 
            getStringIdStringFromId(getNameIdxValueFromId(i)));
    }
    return true;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿field_id_list指定下标的结构首地址
 * 函数参数: nIndex要获取的下标
 * 函数返回值：该下标的结构体指针
 */
///////////////////////////////////////////////////////////////////////////
STFieldIdItem* CMyDexObj::getFieldIdSTFromId(uint nIndex)
{
    ASSERT(m_pFieldIdItem != NULL);
    ASSERT(getFieldIdSizeFromSave() > nIndex && nIndex >= 0);
    return &m_pFieldIdItem[nIndex];
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：从MethodId结构中拿class_idx_字段值
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getClassIdxValueFromId(uint nIndex)
{
	PSTMethodIdItem pST = getMethodIdSTFromId(nIndex);
	return pST->class_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：从MethodId结构中拿proto_idx_字段值
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getProtoIdxValueFromId(uint nIndex)
{
	PSTMethodIdItem pST = getMethodIdSTFromId(nIndex);
	return pST->proto_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：从MethodId结构中拿name_idx_字段值
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getNameIdxValueFromId(uint nIndex)
{
	PSTMethodIdItem pST = getMethodIdSTFromId(nIndex);
	return pST->name_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取FieldIdSize个数
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getFieldIdSizeFromSave()
{
    return m_nFieldIdItemSize;
}

///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿field_id_item数组指定下标的class_idx_字段值
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getFieldClassIdxValueFromIndex(uint nIndex)
{
	STFieldIdItem *pST = getFieldIdSTFromId(nIndex);
	return pST->class_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿field_id_item数组指定下标的type_idx_字段值
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getFieldTypeIdxValueFromIndex(uint nIndex)
{
	STFieldIdItem *pST = getFieldIdSTFromId(nIndex);
	return pST->type_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿field_id_item数组指定下标的name_idx_字段值
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getFieldNameIdxValueFromIndex(uint nIndex)
{
	STFieldIdItem *pST = getFieldIdSTFromId(nIndex);
	return pST->name_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿field_id_item数组指定下标的type_idx_表示的字符串
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getFieldTypeIdxStringFromId(uint nIndex)
{
	//获取type_idx_字段值,这个字段即为type_ids_字符串数组下标
	//m_pDexObj->getTypeIdStringFromId(m_pDexObj->getProto_Idx_FromId(i)), 
	return getTypeIdStringFromId(getFieldTypeIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿field_id_item数组指定下标的class_idx_表示的字符串
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getFieldClassIdxStringFromId(uint nIndex)
{
	//获取class_idx_字段值，这个字段即为type_ids_字符串数组下标
	//m_pDexObj->getTypeIdStringFromId(m_pDexObj->getClass_Idx_FromId(i)), 
	return getTypeIdStringFromId(getFieldClassIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿field_id_item数组指定下标的name_idx_表示的字符串
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getFieldNameIdxStringFromId(uint nIndex)
{
	//获取name_idx_字段值,这个字段即为type_ids_字符串数组下标
	//m_pDexObj->getStringIdStringFromId(m_pDexObj->getName_Idx_FromId(i))
	return getStringIdStringFromId(getFieldNameIdxValueFromIndex(nIndex));
}

///////////////////////////////////////////////////////////////////////////
/* 函数功能：初始化method_id_item必要结构
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::initMethodIdItemST()
{
    //遍历MapItem是否存在对应类型结构数据
    STMapItem *pST = (STMapItem *)getMapItemWithType(kDexTypeMethodIdItem);
    //如果存在
    if((DWORD)pST != EERROR)
    {
        //保存指向MethodIdItem的指针=MapItem结构指向的偏移+文件头地址
        m_pMethodIdItem = (STMethodIdItem*)((DWORD)pST->offset_ + getFileBeginAddr());
        //保存ProtoIdItem个数
        m_nMethodIdItemSize = pST->size_;
        //ColletionMethodIdItem();
    }
    return (DWORD)m_pMethodIdItem != EERROR;
}
bool CMyDexObj::ColletionMethodIdItem()     //收集method_id_item表
{
    STMethodIdItem *pST = NULL;
    for (DWORD i = 0; i < getMethodIdSizeFromSave(); i++)
    {
        //获取该下标类型的地址
        pST = getMethodIdSTFromId(i);
        ASSERT(pST != NULL);
#ifdef DEBUGLOG
        //输出相关结构数据
        printf("[%d]: class_idx: %X proto_idx_: %X name_idx: %X\r\n",
            i, pST->class_idx_, pST->proto_idx_, pST->name_idx_);
#endif 
//         printf("[%d]: class_idx: %s proto_idx_: %s name_idx: %s\r\n",
//             i, 
//             getTypeIdStringFromId(pST->class_idx_), 
//             getProtoIdStringFromId(pST->proto_idx_), 
//             getStringIdStringFromId(pST->name_idx_));
        printf("[%d]: class_idx: %s proto_idx_: ",
            i, 
            getTypeIdStringFromId(pST->class_idx_));
        getProtoIdStringFromId(pST->proto_idx_);
        printf(" name_idx: %s\r\n", getStringIdStringFromId(pST->name_idx_));
    }
    return true;
}
STMethodIdItem* CMyDexObj::getMethodIdSTFromId(uint nIndex)   //拿method_id_list指定下标的结构首地址
{
    ASSERT(m_pMethodIdItem != NULL);
    ASSERT(getMethodIdSizeFromSave() > nIndex && nIndex >= 0);
    return &m_pMethodIdItem[nIndex];
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取FieldIdSize个数
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getMethodIdSizeFromSave()
{
    ASSERT(m_nMethodIdItemSize != 0);
    return m_nMethodIdItemSize;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：显示方法字符串
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
void CMyDexObj::showMethodStringAt(uint nIndex)
{
    ASSERT(m_pMethodIdItem != NULL);
    ASSERT(getMethodIdSizeFromSave() > nIndex && nIndex >= 0);
    STMethodIdItem *pSTMI = &m_pMethodIdItem[nIndex];
    getProtoIdStringFromId(pSTMI->proto_idx_);
    printf(" %s.%s\r\n",
        getTypeIdStringFromId(pSTMI->class_idx_), 
        getStringIdStringFromId(pSTMI->name_idx_));
}

///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿method_id_item数组指定下标方法的类字符串
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getMethodClassIdxStringFromIndex(uint nIndex)
{
	return getTypeIdStringFromId(getMethodClassIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿method_id_item数组指定下标方法的方法原型字符串
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getMethodProtoIdxStringFromIndex(uint nIndex)
{
	return getProtoIdStringFromId(getMethodProtoIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿method_id_item数组指定下标方法的方法名字符串
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getMethodNameIdxStringFromIndex(uint nIndex)
{
	return getStringIdStringFromId(getMethodNameIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿method_id_item数组指定下标的class_idx_字段值
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getMethodClassIdxValueFromIndex(uint nIndex)
{
    STMethodIdItem *pST = getMethodIdSTFromId(nIndex);
	return pST->class_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿method_id_item数组指定下标的proto_idx_字段值
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getMethodProtoIdxValueFromIndex(uint nIndex)
{
    STMethodIdItem *pST = getMethodIdSTFromId(nIndex);
	return pST->proto_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿method_id_item数组指定下标的name_idx_字段值
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getMethodNameIdxValueFromIndex(uint nIndex)
{
    STMethodIdItem *pST = getMethodIdSTFromId(nIndex);
	return pST->name_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：初始化classdef_item必要结构
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::initClassDefItemST()
{
    //遍历MapItem是否存在对应类型结构数据
    STMapItem *pST = (STMapItem *)getMapItemWithType(kDexTypeClassDefItem);
    //如果存在
    if((DWORD)pST != EERROR)
    {
        //保存指向MethodIdItem的指针=MapItem结构指向的偏移+文件头地址
        m_pClassDefItem = (STClassDefItem*)((DWORD)pST->offset_ + 
                            getFileBeginAddr());
        //保存ProtoIdItem个数
        m_nClassDefItemSize = pST->size_;
        //ColletionClassDefItem();
    }
    return (DWORD)m_pClassDefItem != EERROR;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：收集ClassDef_item表
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::ColletionClassDefItem()
{
    STClassDefItem *pST = NULL;
    for (DWORD i = 0; i < getClassDefSizeFromSave(); i++)
    {
        //获取该下标类型的地址
        pST = getClassDefSTFromId(i);
        ASSERT(pST != NULL);
#ifdef DEBUGLOG
        //输出相关结构数据
        printf("[%d]: class_idx:%X pad1:%X access_flags_:%X superclass_idx_:%X "
               "pad2_:%X "
               "interfaces_off_:%X source_file_idx_:%X annotations_off_:%X "
               "class_data_off_:%X static_values_off_:%X\r\n",
            i, pST->class_idx_, pST->pad1_, pST->access_flags_, pST->superclass_idx_,
            pST->pad2_, pST->interfaces_off_, pST->source_file_idx_,
            pST->annotations_off_, pST->class_data_off_,
            pST->static_values_off_);
#endif 
        printf("[%d]: class_idx:%s access_flags_:", 
                i, 
                getTypeIdStringFromId(pST->class_idx_));
        
        //输出访问标志
        uint32_t nAccessFlags = pST->access_flags_;
        //int xx = sizeof(g_AccessFlags) / sizeof(g_AccessFlags[0]);
        for (int j = 0; j < 29; j++)
        {
            switch(nAccessFlags & g_AccessFlags[j])
            {
            case kAccPublic:
                printf(" %s", "ACC_PUBLIC");
                break;
            case kAccPrivate:
                printf(" %s", "ACC_PRIVATE");
                break;
            case kAccProtected:
                printf(" %s", "ACC_PROTECTED");
                break;
            case kAccStatic:
                printf(" %s", "ACC_STATIC");
                break;
            case kAccFinal:
                printf(" %s", "ACC_FINAL");
                break;
            case kAccSynchronized:
                printf(" %s", "ACC_SYNCHRONIZED");
                break;
//             case kAccSuper: //有重复定义
//                 printf(" %s", "ACC_SUPER");
//                 break;
            case kAccVolatile:
                printf(" %s", "ACC_VOLATILE");
                break;
//             case kAccBridge: //有重复定义
//                 printf(" %s", "ACC_BRIDGE");
//                 break;
            case kAccTransient:
                printf(" %s", "ACC_TRANSIENT");
                break;
//             case kAccVarargs: //有重复定义
//                 printf(" %s", "ACC_VARARGS");
//                 break;
            case kAccNative:
                printf(" %s", "ACC_NATIVE");
                break;
            case kAccInterface:
                printf(" %s", "ACC_INTERFACE");
                break;
            case kAccAbstract:
                printf(" %s", "ACC_ABSTRACT");
                break;
            case kAccStrict:
                printf(" %s", "ACC_STRICT");
                break;
            case kAccSynthetic:
                printf(" %s", "ACC_SYNTHETIC");
                break;
            case kAccAnnotation:
                printf(" %s", "ACC_ANNOTATION");
                break;
            case kAccEnum:
                printf(" %s", "ACC_ENUM");
                break;
            case kAccMiranda:
                printf(" %s", "ACC_Miranda");
                break;
//             case kAccJavaFlagsMask:
//                 printf(" %s", "ACC_JavaFlagsMask");
//                 break;
            case kAccConstructor:
                printf(" %s", "ACC_Constructor");
                break;
            case kAccDeclaredSynchronized:
                printf(" %s", "ACC_DeclaredSynchronized");
                break;
            case kAccClassIsProxy:
                printf(" %s", "ACC_ClassIsProxy");
                break;
            case kAccPreverified:
                printf(" %s", "ACC_Preverified");
                break;
            case kAccClassIsFinalizable:
                printf(" %s", "ACC_ClassIsFinalizable");
                break;
            case kAccClassIsReference:
                printf(" %s", "ACC_ClassIsReference");
                break;
            case kAccClassIsWeakReference:
                printf(" %s", "ACC_ClassIsWeakReference");
                break;
            case kAccClassIsFinalizerReference:
                printf(" %s", "ACC_ClassIsFinalizerReference");
                break;
            case kAccClassIsPhantomReference:
                printf(" %s", "ACC_ClassIsPhantomReference");
                break;
            }
        }

        printf(" superclass_idx_:%s "
               "interfaces_off_:%X source_file_idx_:%s annotations_off_:%X "
               "class_data_off_:%X static_values_off_:%X\r\n",
               getTypeIdStringFromId(pST->superclass_idx_),
               pST->interfaces_off_, 
               getStringIdStringFromId(pST->source_file_idx_),
               pST->annotations_off_, 
               pST->class_data_off_,
                pST->static_values_off_);

        //输出interfaces_off相关信息
        TypeList *pTL = NULL;
        //当interfaces_off_不为0
        if (pST->interfaces_off_ != 0)
        {
            //偏移+首地址
            pTL = (TypeList*)((DWORD)pST->interfaces_off_ + getFileBeginAddr());
            uint nSize = pTL->size_;
            STTypeItem *pSTTI = NULL;
            //获取实际Item
            pSTTI = (STTypeItem*)(&pTL->list_);
            printf("\t interfaces Size:%d ", nSize);
            //遍历输出
            for (uint32_t k = 0; k < nSize; k++)
            {
                printf(" (%X)%s", pSTTI[k].type_idx_, 
                    getTypeIdStringFromId(pSTTI[k].type_idx_));
            }
            printf("\r\n");
        }

        //uint annotations_off
        pSTAnnotationsDirectoryItem pAnnotationsDirectoryItem = NULL;
        if (pST->annotations_off_ != 0)
        {
            pAnnotationsDirectoryItem = (pSTAnnotationsDirectoryItem)
                ((DWORD)pST->annotations_off_ + getFileBeginAddr());
            printf("\t class_annotations_off_:%X fields_size_:%X "
                "methods_size_:%X parameters_size_:%X\r\n",
                pAnnotationsDirectoryItem->class_annotations_off_,
                pAnnotationsDirectoryItem->fields_size_,
                pAnnotationsDirectoryItem->methods_size_,
                pAnnotationsDirectoryItem->parameters_size_);
            uint nSize = pAnnotationsDirectoryItem->fields_size_;
        }
        
        //class_def_item->class_data_off_
        pSTClassDataItem pClassDataItem = NULL;
        if (pST->class_data_off_ != 0)
        {
            pClassDataItem = (pSTClassDataItem)
                ((DWORD)pST->class_data_off_ + getFileBeginAddr());
            int nCount = 0;
            pSTClassDataItem pNew = pClassDataItem;
            //各个数量都是leb128数据表示
            int nstatic_fields_size_ = readLeb128((BYTE*)pNew);
            nCount = getLeb128Size((BYTE*)pNew);
            pNew = (pSTClassDataItem)((DWORD)pNew + nCount);
            int ninstance_fields_size_ = readLeb128((BYTE*)pNew);
            nCount = getLeb128Size((BYTE*)pNew);
            pNew = (pSTClassDataItem)((DWORD)pNew + nCount);
            int ndirect_methods_size_ = readLeb128((BYTE*)pNew);
            nCount = getLeb128Size((BYTE*)pNew);
            pNew = (pSTClassDataItem)((DWORD)pNew + nCount);
            int nvirtual_methods_size_ = readLeb128((BYTE*)pNew);
            nCount = getLeb128Size((BYTE*)pNew);
            pNew = (pSTClassDataItem)((DWORD)pNew + nCount);

            printf("\t static_fields_size_:%x instance_fields_size_:%d "
                "direct_methods_size_:%d virtual_methods_size_:%d\r\n",
                nstatic_fields_size_,
                ninstance_fields_size_,
                ndirect_methods_size_,
                nvirtual_methods_size_);

            int nmethod_idx_diff = 0;
            //如果nstatic_fields_size_有效
            if (nstatic_fields_size_)
            {
                printf("\t\t nstatic_fields_size_[%d]\r\n", nstatic_fields_size_);
                for (int i = 0; i < nstatic_fields_size_; i++)
                {
                    //域信息输出
                    //指向fieldids字下标
                    int field_idx_diff = readLeb128((BYTE*)pNew);
                    nCount = getLeb128Size((BYTE*)pNew);
                    pNew = (pSTClassDataItem)((DWORD)pNew + nCount);
                    
                    //访问标志
                    int naccess_flags = readLeb128((BYTE*)pNew);
                    nCount = getLeb128Size((BYTE*)pNew);
                    pNew = (pSTClassDataItem)((DWORD)pNew + nCount);
                    

//                     printf("\t\t\t[%X => %d]", nmethod_idx_diff, nmethod_idx_diff);
//                     showMethodStringAt(nmethod_idx_diff);
                    printf("\t\t\t [%d]method_idx_diff:%X access_flags:%X \r\n", 
                        i,
                        field_idx_diff,
                        naccess_flags);
                }
            }

            //如果ninstance_fields_size_有效
            if (ninstance_fields_size_)
            {
                printf("\t\t ninstance_fields_size_[%d]\r\n", ninstance_fields_size_);
                for (int i = 0; i < ninstance_fields_size_; i++)
                {
                    //域信息输出
                    //指向fieldids字下标
                    int field_idx_diff = readLeb128((BYTE*)pNew);
                    nCount = getLeb128Size((BYTE*)pNew);
                    pNew = (pSTClassDataItem)((DWORD)pNew + nCount);
                    
                    //访问标志
                    int naccess_flags = readLeb128((BYTE*)pNew);
                    nCount = getLeb128Size((BYTE*)pNew);
                    pNew = (pSTClassDataItem)((DWORD)pNew + nCount);
                    
                    printf("\t\t\t [%d]method_idx_diff:%X access_flags:%X \r\n", 
                        i,
                        field_idx_diff,
                        naccess_flags);
                }
            }

            //如果ndirect_methods_size_有效
            if (ndirect_methods_size_)
            {
                printf("\t\t ndirect_methods_size_[%d]\r\n", ndirect_methods_size_);
                for (int i = 0; i < ndirect_methods_size_; i++)
                {
                    //方法输出
                    nmethod_idx_diff = readLeb128((BYTE*)pNew);
                    nCount = getLeb128Size((BYTE*)pNew);
                    pNew = (pSTClassDataItem)((DWORD)pNew + nCount);
                    
                    int naccess_flags = readLeb128((BYTE*)pNew);
                    nCount = getLeb128Size((BYTE*)pNew);
                    pNew = (pSTClassDataItem)((DWORD)pNew + nCount);
                    
                    int ncode_off = readLeb128((BYTE*)pNew);
                    nCount = getLeb128Size((BYTE*)pNew);
                    pNew = (pSTClassDataItem)((DWORD)pNew + nCount);
                    
//                     printf("\t\t\t[%X => %d]", nmethod_idx_diff, nmethod_idx_diff);
//                     showMethodStringAt(nmethod_idx_diff);
                    printf("\t\t\t [%d]method_idx_diff:%X access_flags:%X "
                        "code_off:%X\r\n", 
                        i,
                        nmethod_idx_diff,
                        naccess_flags,
                        ncode_off);
                    printf("\t\t\t [%d]method_idx_diff:%X access_flags: ",
                        i,
                        nmethod_idx_diff);
                    //显示access_flags

                    //int xx = sizeof(g_AccessFlags) / sizeof(g_AccessFlags[0]);
                    for (int j = 0; j < 29; j++)
                    {
                        switch(naccess_flags & g_AccessFlags[j])
                        {
                        case kAccPublic:
                            printf(" %s", "ACC_PUBLIC");
                            break;
                        case kAccPrivate:
                            printf(" %s", "ACC_PRIVATE");
                            break;
                        case kAccProtected:
                            printf(" %s", "ACC_PROTECTED");
                            break;
                        case kAccStatic:
                            printf(" %s", "ACC_STATIC");
                            break;
                        case kAccFinal:
                            printf(" %s", "ACC_FINAL");
                            break;
                        case kAccSynchronized:
                            printf(" %s", "ACC_SYNCHRONIZED");
                            break;
                            //             case kAccSuper: //有重复定义
                            //                 printf(" %s", "ACC_SUPER");
                            //                 break;
                        case kAccVolatile:
                            printf(" %s", "ACC_VOLATILE");
                            break;
                            //             case kAccBridge: //有重复定义
                            //                 printf(" %s", "ACC_BRIDGE");
                            //                 break;
                        case kAccTransient:
                            printf(" %s", "ACC_TRANSIENT");
                            break;
                            //             case kAccVarargs: //有重复定义
                            //                 printf(" %s", "ACC_VARARGS");
                            //                 break;
                        case kAccNative:
                            printf(" %s", "ACC_NATIVE");
                            break;
                        case kAccInterface:
                            printf(" %s", "ACC_INTERFACE");
                            break;
                        case kAccAbstract:
                            printf(" %s", "ACC_ABSTRACT");
                            break;
                        case kAccStrict:
                            printf(" %s", "ACC_STRICT");
                            break;
                        case kAccSynthetic:
                            printf(" %s", "ACC_SYNTHETIC");
                            break;
                        case kAccAnnotation:
                            printf(" %s", "ACC_ANNOTATION");
                            break;
                        case kAccEnum:
                            printf(" %s", "ACC_ENUM");
                            break;
                        case kAccMiranda:
                            printf(" %s", "ACC_Miranda");
                            break;
//                         case kAccJavaFlagsMask:
//                             printf(" %s", "ACC_JavaFlagsMask");
//                             break;
                        case kAccConstructor:
                            printf(" %s", "ACC_Constructor");
                            break;
                        case kAccDeclaredSynchronized:
                            printf(" %s", "ACC_DeclaredSynchronized");
                            break;
                        case kAccClassIsProxy:
                            printf(" %s", "ACC_ClassIsProxy");
                            break;
                        case kAccPreverified:
                            printf(" %s", "ACC_Preverified");
                            break;
                        case kAccClassIsFinalizable:
                            printf(" %s", "ACC_ClassIsFinalizable");
                            break;
                        case kAccClassIsReference:
                            printf(" %s", "ACC_ClassIsReference");
                            break;
                        case kAccClassIsWeakReference:
                            printf(" %s", "ACC_ClassIsWeakReference");
                            break;
                        case kAccClassIsFinalizerReference:
                            printf(" %s", "ACC_ClassIsFinalizerReference");
                            break;
                        case kAccClassIsPhantomReference:
                            printf(" %s", "ACC_ClassIsPhantomReference");
                            break;
                        }
                    }

                    printf(" code_off:%X\r\n", 
                        ncode_off);
                    if(ncode_off != 0)
                    {
                        pSTCodeItem pSTCI = (pSTCodeItem)((DWORD)ncode_off + getFileBeginAddr());
                        printf("\t\t\t\t registers_size:%d "
                            "ins_size:%d outs_size:%d tries_size:%d "
                            "debug_info_off:%X insns_size:%d\r\n",
                            pSTCI->registers_size_,
                            pSTCI->ins_size_,
                            pSTCI->outs_size_,
                            pSTCI->tries_size_,
                            pSTCI->debug_info_off_,
                            pSTCI->insns_size_in_code_units_);
                        //如果code字节码不为空
                        if(pSTCI->insns_size_in_code_units_ != 0)
                        {
                            printf("\t\t\t\t\t");
                            for (uint32_t i = 0; i < pSTCI->insns_size_in_code_units_;
                            i++)
                            {
                                //2个字节读出
                                uint16_t code = pSTCI->insns_[i];
                                
                                printf(" %02X %02X", (BYTE)(code & 0xff),
                                    (BYTE)((code >> 8) & 0xff));
                            }
                            printf("\r\n");
                        }
                    } //if(ncode_off != 0)
                }
            }

            //如果nvirtual_methods_size_有效
            if (nvirtual_methods_size_)
            {
                printf("\t\t nnvirtual_methods_size_[%d]\r\n", nvirtual_methods_size_);
                for (int i = 0; i < nvirtual_methods_size_; i++)
                {
                    //方法输出
                    nmethod_idx_diff = readLeb128((BYTE*)pNew);
                    nCount = getLeb128Size((BYTE*)pNew);
                    pNew = (pSTClassDataItem)((DWORD)pNew + nCount);
                    
                    int naccess_flags = readLeb128((BYTE*)pNew);
                    nCount = getLeb128Size((BYTE*)pNew);
                    pNew = (pSTClassDataItem)((DWORD)pNew + nCount);
                    
                    int ncode_off = readLeb128((BYTE*)pNew);
                    nCount = getLeb128Size((BYTE*)pNew);
                    pNew = (pSTClassDataItem)((DWORD)pNew + nCount);
                    
//                     printf("\t\t\t[%X => %d]", nmethod_idx_diff, nmethod_idx_diff);
//                     showMethodStringAt(nmethod_idx_diff);

//                     printf("\t\t\t [%d]method_idx_diff:%X access_flags:%X "
//                         "code_off:%X\r\n", 
//                         i,
//                         nmethod_idx_diff,
//                         naccess_flags,
//                         ncode_off);
                    
                    printf("\t\t\t [%d]method_idx_diff:%X access_flags:%X "
                        "code_off:%X\r\n", 
                        i,
                        nmethod_idx_diff,
                        naccess_flags,
                        ncode_off);
                    printf("\t\t\t [%d]method_idx_diff:%X access_flags: ",
                        i,
                        nmethod_idx_diff);
                    //显示access_flags

                    //int xx = sizeof(g_AccessFlags) / sizeof(g_AccessFlags[0]);
                    for (int j = 0; j < 29; j++)
                    {
                        switch(naccess_flags & g_AccessFlags[j])
                        {
                        case kAccPublic:
                            printf(" %s", "ACC_PUBLIC");
                            break;
                        case kAccPrivate:
                            printf(" %s", "ACC_PRIVATE");
                            break;
                        case kAccProtected:
                            printf(" %s", "ACC_PROTECTED");
                            break;
                        case kAccStatic:
                            printf(" %s", "ACC_STATIC");
                            break;
                        case kAccFinal:
                            printf(" %s", "ACC_FINAL");
                            break;
                        case kAccSynchronized:
                            printf(" %s", "ACC_SYNCHRONIZED");
                            break;
                            //             case kAccSuper: //有重复定义
                            //                 printf(" %s", "ACC_SUPER");
                            //                 break;
                        case kAccVolatile:
                            printf(" %s", "ACC_VOLATILE");
                            break;
                            //             case kAccBridge: //有重复定义
                            //                 printf(" %s", "ACC_BRIDGE");
                            //                 break;
                        case kAccTransient:
                            printf(" %s", "ACC_TRANSIENT");
                            break;
                            //             case kAccVarargs: //有重复定义
                            //                 printf(" %s", "ACC_VARARGS");
                            //                 break;
                        case kAccNative:
                            printf(" %s", "ACC_NATIVE");
                            break;
                        case kAccInterface:
                            printf(" %s", "ACC_INTERFACE");
                            break;
                        case kAccAbstract:
                            printf(" %s", "ACC_ABSTRACT");
                            break;
                        case kAccStrict:
                            printf(" %s", "ACC_STRICT");
                            break;
                        case kAccSynthetic:
                            printf(" %s", "ACC_SYNTHETIC");
                            break;
                        case kAccAnnotation:
                            printf(" %s", "ACC_ANNOTATION");
                            break;
                        case kAccEnum:
                            printf(" %s", "ACC_ENUM");
                            break;
                        case kAccMiranda:
                            printf(" %s", "ACC_Miranda");
                            break;
//                         case kAccJavaFlagsMask:
//                             printf(" %s", "ACC_JavaFlagsMask");
//                             break;
                        case kAccConstructor:
                            printf(" %s", "ACC_Constructor");
                            break;
                        case kAccDeclaredSynchronized:
                            printf(" %s", "ACC_DeclaredSynchronized");
                            break;
                        case kAccClassIsProxy:
                            printf(" %s", "ACC_ClassIsProxy");
                            break;
                        case kAccPreverified:
                            printf(" %s", "ACC_Preverified");
                            break;
                        case kAccClassIsFinalizable:
                            printf(" %s", "ACC_ClassIsFinalizable");
                            break;
                        case kAccClassIsReference:
                            printf(" %s", "ACC_ClassIsReference");
                            break;
                        case kAccClassIsWeakReference:
                            printf(" %s", "ACC_ClassIsWeakReference");
                            break;
                        case kAccClassIsFinalizerReference:
                            printf(" %s", "ACC_ClassIsFinalizerReference");
                            break;
                        case kAccClassIsPhantomReference:
                            printf(" %s", "ACC_ClassIsPhantomReference");
                            break;
                        }
                    }

                    printf(" code_off:%X\r\n", 
                        ncode_off);
                    if(ncode_off != 0)
                    {
                        pSTCodeItem pSTCI = (pSTCodeItem)((DWORD)ncode_off + getFileBeginAddr());
                        printf("\t\t\t\t registers_size:%d "
                            "ins_size:%d outs_size:%d tries_size:%d "
                            "debug_info_off:%X insns_size:%d\r\n",
                            pSTCI->registers_size_,
                            pSTCI->ins_size_,
                            pSTCI->outs_size_,
                            pSTCI->tries_size_,
                            pSTCI->debug_info_off_,
                            pSTCI->insns_size_in_code_units_);
                        //如果code字节码不为空
                        if(pSTCI->insns_size_in_code_units_ != 0)
                        {
                            printf("\t\t\t\t\t");
                            for (uint32_t i = 0; i < pSTCI->insns_size_in_code_units_;
                                 i++)
                            {
                                     //2个字节读出
                                     uint16_t code = pSTCI->insns_[i];

                                     printf(" %02X %02X", (BYTE)(code & 0xff),
                                         (BYTE)((code >> 8) & 0xff));
                            }
                                 printf("\r\n");
                        }
                    } //if(ncode_off != 0)
                }
            } //if (nvirtual_methods_size_)
        } //if (pST->class_data_off_ != 0)
    } //for (DWORD i = 0; i < getClassDefSizeFromSave(); i++)
    return true;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿ClassDef_list指定下标的结构首地址
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
STClassDefItem* CMyDexObj::getClassDefSTFromId(uint nIndex)
{
    ASSERT(m_pClassDefItem != NULL);
    ASSERT(getClassDefSizeFromSave() > nIndex && nIndex >= 0);
    return &m_pClassDefItem[nIndex];
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取ClassDefSize个数
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getClassDefSizeFromSave()
{
    ASSERT(m_nClassDefItemSize != 0);
    return m_nClassDefItemSize;
}

///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取class_def_item下标结构中的class_idx_字段值	
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getClassClassIdxValueFromIndex(uint nIndex)
{
	PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
	return pCD->class_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取class_def_item下标结构中的pad1_字段值	
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getClassPad1ValueFromIndex(uint nIndex)
{
	PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
	return pCD->pad1_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取class_def_item下标结构中的access_flags_字段值
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassAccessFlagsValueFromIndex(uint nIndex)
{
	PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
	return pCD->access_flags_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取class_def_item下标结构中的superclass_idx_字段值
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getClassSuperclassIdxValueFromIndex(uint nIndex)
{
	PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
	return pCD->superclass_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取class_def_item下标结构中的pad2_字段值	
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getClassPad2ValueFromIndex(uint nIndex)
{
	PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
	return pCD->pad2_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取class_def_item下标结构中的interfaces_off字段值
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassInterfaceOffValueFromIndex(uint nIndex)
{
	PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
	return pCD->interfaces_off_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取class_def_item下标结构中的source_file_idx_字段值
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassSourceFileIdxValueFromIndex(uint nIndex)
{
	PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
	return pCD->source_file_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取class_def_item下标结构中的annotations_off_字段值
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassAnnotationsOffValueFromIndex(uint nIndex)
{
	PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
	return pCD->annotations_off_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取class_def_item下标结构中的class_data_off_字段值
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassClassDataOffValueFromIndex(uint nIndex)
{
	PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
	return pCD->class_data_off_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取class_def_item下标结构中的static_values_off_字段值
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassStaticValuesOffValueFromIndex(uint nIndex)
{
	PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
	return pCD->static_values_off_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取指定下标的ClassDef结构中的class_idx_的字符串
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getClassClassIdxStringFromIndex(uint nIndex)
{
	return getTypeIdStringFromId(getClassClassIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取指定下标的ClassDef结构中的access_flags_表示的字符串,返回值需要手动做数组释放
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getClassAccessFlagsStringFromIndex(uint nIndex)
{
	DWORD dwFlags = getClassAccessFlagsValueFromIndex(nIndex);
	char *result = new char[MAXBYTE * 4];
	result[0] = '\0';
	char temp[MAXBYTE];

	//若flags为0则返回0
	if(dwFlags == 0)
	{
		result[0] = 0x30;
		result[1] = '\0';
		return result;
	}

    for (int j = 0; j < sizeof(g_AccessFlags) / sizeof(g_AccessFlags[0]); j++)
    {
        switch(dwFlags & g_AccessFlags[j])
        {
        case kAccPublic:
            sprintf(temp, " %s", "ACC_PUBLIC");
			strcat(result, temp);
            break;
        case kAccPrivate:
            sprintf(temp, " %s", "ACC_PRIVATE");
			strcat(result, temp);
            break;
        case kAccProtected:
            sprintf(temp, " %s", "ACC_PROTECTED");
			strcat(result, temp);
            break;
        case kAccStatic:
            sprintf(temp, " %s", "ACC_STATIC");
			strcat(result, temp);
            break;
        case kAccFinal:
            sprintf(temp, " %s", "ACC_FINAL");
			strcat(result, temp);
            break;
        case kAccSynchronized:
            sprintf(temp, " %s", "ACC_SYNCHRONIZED");
			strcat(result, temp);
            break;
			//             case kAccSuper: //有重复定义
			//                 printf(" %s", "ACC_SUPER");
			//                 break;
        case kAccVolatile:
            sprintf(temp, " %s", "ACC_VOLATILE");
			strcat(result, temp);
            break;
			//             case kAccBridge: //有重复定义
			//                 printf(" %s", "ACC_BRIDGE");
			//                 break;
        case kAccTransient:
            sprintf(temp, " %s", "ACC_TRANSIENT");
			strcat(result, temp);
            break;
//             case kAccVarargs: //有重复定义
//                 printf(" %s", "ACC_VARARGS");
//                 break;
        case kAccNative:
            sprintf(temp, " %s", "ACC_NATIVE");
			strcat(result, temp);
            break;
        case kAccInterface:
            sprintf(temp, " %s", "ACC_INTERFACE");
			strcat(result, temp);
            break;
        case kAccAbstract:
            sprintf(temp, " %s", "ACC_ABSTRACT");
			strcat(result, temp);
            break;
        case kAccStrict:
            sprintf(temp, " %s", "ACC_STRICT");
			strcat(result, temp);
            break;
        case kAccSynthetic:
            sprintf(temp, " %s", "ACC_SYNTHETIC");
			strcat(result, temp);
            break;
        case kAccAnnotation:
            sprintf(temp, " %s", "ACC_ANNOTATION");
			strcat(result, temp);
            break;
        case kAccEnum:
            sprintf(temp, " %s", "ACC_ENUM");
			strcat(result, temp);
            break;
        case kAccMiranda:
            sprintf(temp, " %s", "ACC_Miranda");
			strcat(result, temp);
            break;
			//             case kAccJavaFlagsMask:
			//                 printf(" %s", "ACC_JavaFlagsMask");
			//                 break;
        case kAccConstructor:
            sprintf(temp, " %s", "ACC_Constructor");
			strcat(result, temp);
            break;
        case kAccDeclaredSynchronized:
            sprintf(temp, " %s", "ACC_DeclaredSynchronized");
			strcat(result, temp);
            break;
        case kAccClassIsProxy:
            sprintf(temp, " %s", "ACC_ClassIsProxy");
			strcat(result, temp);
            break;
        case kAccPreverified:
            sprintf(temp, " %s", "ACC_Preverified");
			strcat(result, temp);
            break;
        case kAccClassIsFinalizable:
            sprintf(temp, " %s", "ACC_ClassIsFinalizable");
			strcat(result, temp);
            break;
        case kAccClassIsReference:
            sprintf(temp, " %s", "ACC_ClassIsReference");
			strcat(result, temp);
            break;
        case kAccClassIsWeakReference:
            sprintf(temp, " %s", "ACC_ClassIsWeakReference");
			strcat(result, temp);
            break;
        case kAccClassIsFinalizerReference:
            sprintf(temp, " %s", "ACC_ClassIsFinalizerReference");
			strcat(result, temp);
            break;
        case kAccClassIsPhantomReference:
            sprintf(temp, " %s", "ACC_ClassIsPhantomReference");
			strcat(result, temp);
            break;
        }
    }
	return result;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取指定下标的ClassDef结构中的superclass_idx_的字符串
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getClassSuperClassIdxStringFromIndex(uint nIndex)
{
	return getTypeIdStringFromId(getClassSuperclassIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取指定下标的ClassDef结构中的source_file_idx_的字符串
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getClassSourceFileIdxStringFromIndex(uint nIndex)
{
	return getStringIdStringFromId(getClassSourceFileIdxValueFromIndex(nIndex));
}