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
    //文件是否以dex 035开头
    if(m_pHeader->magic_[0] != 'd' || 
        m_pHeader->magic_[1] != 'e' ||
        m_pHeader->magic_[2] != 'x' ||
        m_pHeader->magic_[4] != '0' ||
        m_pHeader->magic_[5] != '3' ||
        m_pHeader->magic_[6] != '5')
    {
        return false;
    }

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
 * 函数返回值：存在返回对应指针，否则返回NULL
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
    return NULL;//(STMapItem *)EERROR;
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
// 	PSTMapItem pSI = getMapItemWithType(kDexTypeStringIdItem);
// 	return pSI->size_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿string_id_list指定下标的字符串
 * 函数参数: 下标
 * 函数返回值：
*/
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getStringIdStringFromIndex(uint nIndex)
{
    ASSERT(nIndex < m_nStringIdItemSize && nIndex >= 0);
    //从stringids数组读出下标的string_data_off字段值，其为文件偏移
    BYTE *pLeb128 = getStringIdsStringDataOffSTFromIndex(nIndex);
    if (!pLeb128)
    {
        return "getStringIdsStringDataOffSTFromIndex ret NULL!";
    }
    //所以要读取数据必须先加上文件首地址
    pLeb128 = (BYTE *)((DWORD)pLeb128 + getFileBeginAddr());
    //item首地址为leb128类型数据来指示这个ITEM中的字符串的长度
    return (char *)((DWORD)pLeb128 + getLeb128Size(pLeb128));
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿string_id_list指定下标的string_data_off字段值，
              其为指向的StringItem结构的文件偏移地址
 * 函数参数: nIndex 目标string_id_list数组下标
 * 函数返回值：
*/
///////////////////////////////////////////////////////////////////////////
uint CMyDexObj::getStringIdsStringDataOffValueFromIndex(uint nIndex)
{
    ASSERT(nIndex < m_nStringIdItemSize && nIndex >= 0);
    return m_pStringItem[nIndex].m_nOffset;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿string_id_list指定下标的string_data_off指向的StringItem的结构文件偏移
 * 函数参数: nIndex 目标string_id_list数组下标
 * 函数返回值：
*/
///////////////////////////////////////////////////////////////////////////
BYTE *CMyDexObj::getStringIdsStringDataOffSTFromIndex(uint nIndex)
{
    return (BYTE*)getStringIdsStringDataOffValueFromIndex(nIndex);
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
    //从stringids数组读出下标的string_data_off字段值
    BYTE *pByte = getStringIdsStringDataOffSTFromIndex(nIndex);
    if (!pByte)
    {
        return 0;
    }
    //返回值实际是结构在文件的偏移地址，所以加上首地址
    pByte = (BYTE *)(DWORD(pByte) + getFileBeginAddr());
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
const char* CMyDexObj::getTypeIdStringFromIndex(uint nIndex)
{
    //调用getStringFromId接口，m_pTypeIdItem[nIndex].descriptor_idx_拿对应下标
    ASSERT(nIndex < m_nTypeIdItemSize && nIndex >= 0);
//     if (!(nIndex < m_nTypeIdItemSize && nIndex >= 0))
//     {
//         printf("m_nTypeIdItemSize:%d nIndex:%d", m_nTypeIdItemSize, nIndex);
//     }
    return getStringIdStringFromIndex(m_pTypeIdItem[nIndex].descriptor_idx_);
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
            getStringIdStringFromIndex(i));
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
        printf("%d ==>%s\r\n", i, getTypeIdStringFromIndex(i));        
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
        pST = getProtoIdsSTFromIndex(i);
        ASSERT(pST != NULL);
#ifdef DEBUGLOG
        //输出相关结构数据
        printf("[%d]: shorty_idx: %X return_type_idx: %X parameters_off: %X\r\n",
            i, pST->shorty_idx_, pST->return_type_idx_, pST->parameters_off_);
#endif 
        printf("[%d]: shorty_idx: %s return_type_idx: %s ",
            i, getStringIdStringFromIndex(pST->shorty_idx_), 
            getTypeIdStringFromIndex(pST->return_type_idx_));//
        const char* pstr = getProtoIdsParametersStringFromIndex(i);
        printf("%s\r\n", pstr);
        delete[] (char*)pstr;
        pstr = getProtoIdsProtoStringFromIndex(i);
        printf("\tProtoIdString: %s\r\n", pstr);
        delete[] (char*)pstr;
    }
    return true;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿ProteIds指定下标方法的极简返回值跟参数字符串
 * 函数参数: nIndex 要获取的protoids下标
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getProtoIdsShortyIdxStringFromIndex(uint nProtoIdsIndex)
{
    //这个ShortyIdx字段实际是指向StringId字符串表的下标，调用返回即可
    return getStringIdStringFromIndex(getProtoIdsShortyIdxValueFromIndex(nProtoIdsIndex));
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿ProteIds指定下标方法的返回类型字符串
 * 函数参数: nIndex protoids下标
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getProtoIdsReturnTypeIdxStringFromIndex(uint nProtoIdsIndex)
{
    //这个return_type_idx_字段实际是指向TypeId字符串表的下标，调用返回即可
    return getTypeIdStringFromIndex(getProtoIdsReturnTypeIdxValueFromIndex(nProtoIdsIndex));
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿指定下标方法的参数列表字符串，返回值需要手动释放delete[] 
 * 函数参数: nIndex proto_ids的下标
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getProtoIdsParametersStringFromIndex(uint nProtoIdsIndex)
{
    char temp[MAXBYTE];
    char *tempret = new char[MAXBYTE * 4];
    tempret[0] = '\0';
    //拿parameters_off字段值
    DWORD dwOff = getProtoIdsParametersOffValueFromIndex(nProtoIdsIndex);
    //没有参数时该off为0 
    if (dwOff != 0)
    {
		//dwOff = (DWORD)getProtoIdsTypeItemListSTFileOffsetFromIndex(nProtoIdsIndex)
        PSTTypeItemList pTL = (PSTTypeItemList)(dwOff + getFileBeginAddr());
        sprintf(temp, "parameters_off[%d]: ", pTL->size_);
        strcpy(tempret, temp);
		//循环加入所有参数
        for (uint j = 0; j < pTL->size_; j++)
        {
            sprintf(temp, "%s ", getTypeIdStringFromIndex(pTL->list_[j].type_idx_));
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
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿指定proto_ids下标的ShortyIdx字段值
 * 函数参数: nIndex proto_ids的下标
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getProtoIdsShortyIdxValueFromIndex(uint nProtoIdsIndex)
{
    //取出proto结构下标数据
    STProtoIdItem *pST = NULL;
    pST = getProtoIdsSTFromIndex(nProtoIdsIndex);
	//异常规避
	if (!pST)
	{
		return 0;
	}
    return pST->shorty_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿指定下标方法的ReturnTypeIdx字段值 
 * 函数参数: nIndex proto_ids的下标
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getProtoIdsReturnTypeIdxValueFromIndex(uint nProtoIdsIndex)
{
    //取出proto结构下标数据
    STProtoIdItem *pST = NULL;
    pST = getProtoIdsSTFromIndex(nProtoIdsIndex);
	//异常规避
	if (!pST)
	{
		return 0;
	}
    return pST->return_type_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿指定下标方法的Parameter字段值
 * 函数参数: nIndex proto_ids的下标
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
// DWORD CMyDexObj::getProtoIdsParametersValueFromIndex(uint nProtoIdsIndex)
// {
//     //取出proto结构下标数据
//     STProtoIdItem *pST = NULL;
//     pST = getProtoIdsSTFromIndex(nProtoIdsIndex);
// 	//异常规避
// 	if (!pST)
// 	{
// 		return 0;
// 	}
//     return pST->parameters_off_;
// }
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿proto_id_list指定下标的proto_id_item结构首地址
 * 函数参数: nIndex要获取的下标
 * 函数返回值：该下标的结构体指针
 */
///////////////////////////////////////////////////////////////////////////
STProtoIdItem* CMyDexObj::getProtoIdsSTFromIndex(uint nProtoIdsIndex)
{
    ASSERT(m_pProtoIdItem != NULL);
    ASSERT(m_nProtoIdItemSize > nProtoIdsIndex && nProtoIdsIndex >= 0);
    return &m_pProtoIdItem[nProtoIdsIndex];
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取指定下标方法的参数列表字段值
 * 函数参数: nIndex要获取的下标
 * 函数返回值：参数列表字段值
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getProtoIdsParametersOffValueFromIndex(uint nIndex)
{
    STProtoIdItem* pST = getProtoIdsSTFromIndex(nIndex);
    if(pST != NULL)
    {
        return pST->parameters_off_;
    }
    return 0;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取指定下标parameters_off指向的TypeItemList
                {uint size; type_item list[size]}结构文件偏移地址，
                若相关参数off为0则返回值为空
 * 函数参数: nIndex要获取的下标
 * 函数返回值：该下标的结构体指针
 */
///////////////////////////////////////////////////////////////////////////
STTypeItemList *CMyDexObj::getProtoIdsTypeItemListSTFileOffsetFromIndex(uint nIndex)
{
    return (STTypeItemList *)getProtoIdsParametersOffValueFromIndex(nIndex);
//     DWORD dwParametersOff = getProtoIdsParametersOffValueFromIndex(nIndex);
//     //参数列表不为空才读取返回
//     if(dwParametersOff != 0)
//     {
//         //循环输出参数
//         STTypeItemList *pTL = (STTypeItemList *)(dwParametersOff);
//         return pTL;
//     }
//     return NULL;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：组合proto_id_list数组指定下标的函数原型信息,返回值需要手动释放
 * 函数参数: nIndex要获取的proto_ids下标
 * 函数返回值：该下标的结构体指针
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getProtoIdsProtoStringFromIndex(uint nIndex)
{
    char temp[MAXBYTE];
    char *Tempret = new char[MAXBYTE *4];
    Tempret[0] = '\0';
    STProtoIdItem* pST = getProtoIdsSTFromIndex(nIndex);
    if(pST != NULL)
    {
        //返回值（参数列表）
        sprintf(Tempret, "%s (", getTypeIdStringFromIndex(pST->return_type_idx_));
		//获取parameter_off字段值
        DWORD dwOff = getProtoIdsParametersOffValueFromIndex(nIndex);
        //参数列表不为空才需要输出 
        if(dwOff)
        {
            //循环输出参数
            STTypeItemList *pTL = (STTypeItemList *)(dwOff + getFileBeginAddr());
            for (DWORD i = 0; i < pTL->size_; i++)
            {
                sprintf(temp, " %s", getTypeIdStringFromIndex(pTL->list_[i].type_idx_));
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
    //如果返回不为空
    if(pST)
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
        pST = getFieldIdSTFromIndex(i);
        ASSERT(pST != NULL);
#ifdef DEBUGLOG
        //输出相关结构数据
        printf("[%d]: class_idx: %X type_idx: %X name_idx: %X\r\n",
            i, pST->class_idx_, pST->type_idx_, pST->name_idx_);
#endif 
        printf("[%d]: class_idx: %s type_idx: %s name_idx: %s\r\n",
            i, 
            getTypeIdStringFromIndex(getFieldIdsClassIdxValueFromIndex(i)), 
            getTypeIdStringFromIndex(getFieldIdsTypeIdxValueFromIndex(i)), 
            getStringIdStringFromIndex(getFieldIdsNameIdxValueFromIndex(i)));
    }
    return true;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿field_id_list指定下标的field_id_item结构首地址
 * 函数参数: nIndex要获取的fieldsids下标
 * 函数返回值：该下标的结构体指针
 */
///////////////////////////////////////////////////////////////////////////
STFieldIdItem* CMyDexObj::getFieldIdSTFromIndex(uint nIndex)
{
    ASSERT(m_pFieldIdItem != NULL);
    ASSERT(getFieldIdSizeFromSave() > nIndex && nIndex >= 0);
    return &m_pFieldIdItem[nIndex];
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：从MethodId结构中拿指定下标的field_id_item结构的class_idx_字段值
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getFieldIdsClassIdxValueFromIndex(uint nIndex)
{
	PSTFieldIdItem pST = getFieldIdSTFromIndex(nIndex);
    if (!pST)
    {
        return 0;
    }
	return pST->class_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：从MethodId结构中拿指定下标的field_id_item结构的proto_idx_字段值
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getFieldIdsTypeIdxValueFromIndex(uint nIndex)
{
    PSTFieldIdItem pST = getFieldIdSTFromIndex(nIndex);
    if (!pST)
    {
        return 0;
    }
	return pST->type_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：从FieldId结构中拿指定下标的field_id_item结构的name_idx_字段值
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getFieldIdsNameIdxValueFromIndex(uint nIndex)
{
    PSTFieldIdItem pST = getFieldIdSTFromIndex(nIndex);
    if (!pST)
    {
        return 0;
    }
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
// DWORD CMyDexObj::getFieldClassIdxValueFromIndex(uint nIndex)
// {
// 	STFieldIdItem *pST = getFieldIdSTFromIndex(nIndex);
//     if (!pST)
//     {
//         return 0;
//     }
// 	return pST->class_idx_;
// }
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿field_id_item数组指定下标的type_idx_字段值
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
// DWORD CMyDexObj::getFieldTypeIdxValueFromIndex(uint nIndex)
// {
//     STFieldIdItem *pST = getFieldIdSTFromIndex(nIndex);
//     if (!pST)
//     {
//         return 0;
//     }
// 	return pST->type_idx_;
// }
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿field_id_item数组指定下标的name_idx_字段值
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
// DWORD CMyDexObj::getFieldNameIdxValueFromIndex(uint nIndex)
// {
//     STFieldIdItem *pST = getFieldIdSTFromIndex(nIndex);
//     if (!pST)
//     {
//         return 0;
//     }
// 	return pST->name_idx_;
// }
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿field_id_item数组指定下标的type_idx_表示的字符串
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getFieldTypeIdxStringFromIndex(uint nIndex)
{
	//获取type_idx_字段值,这个字段即为type_ids_字符串数组下标
	//m_pDexObj->getTypeIdStringFromId(m_pDexObj->getProto_Idx_FromId(i)), 
	return getTypeIdStringFromIndex(getFieldIdsTypeIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿field_id_item数组指定下标的class_idx_表示的字符串
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getFieldClassIdxStringFromIndex(uint nIndex)
{
	//获取class_idx_字段值，这个字段即为type_ids_字符串数组下标
	//m_pDexObj->getTypeIdStringFromId(m_pDexObj->getClass_Idx_FromId(i)), 
	return getTypeIdStringFromIndex(getFieldIdsClassIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿field_id_item数组指定下标的name_idx_表示的字符串
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getFieldNameIdxStringFromIndex(uint nIndex)
{
	//获取name_idx_字段值,这个字段即为type_ids_字符串数组下标
	//m_pDexObj->getStringIdStringFromId(m_pDexObj->getName_Idx_FromId(i))
	return getStringIdStringFromIndex(getFieldIdsNameIdxValueFromIndex(nIndex));
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
        pST = getMethodIdSTFromIndex(i);
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
            getTypeIdStringFromIndex(pST->class_idx_));
        getProtoIdsProtoStringFromIndex(pST->proto_idx_);
        printf(" name_idx: %s\r\n", getStringIdStringFromIndex(pST->name_idx_));
    }
    return true;
}
STMethodIdItem* CMyDexObj::getMethodIdSTFromIndex(uint nIndex)   //拿method_id_list指定下标的结构首地址
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
    getProtoIdsProtoStringFromIndex(pSTMI->proto_idx_);
    printf(" %s.%s\r\n",
        getTypeIdStringFromIndex(pSTMI->class_idx_), 
        getStringIdStringFromIndex(pSTMI->name_idx_));
}

///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿method_id_item数组指定下标方法的类字符串
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getMethodClassIdxStringFromIndex(uint nIndex)
{
	return getTypeIdStringFromIndex(getMethodClassIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿method_id_item数组指定下标方法的方法原型字符串
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getMethodProtoIdxStringFromIndex(uint nIndex)
{
	return getProtoIdsProtoStringFromIndex(getMethodProtoIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿method_id_item数组指定下标方法的方法名字符串
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getMethodNameIdxStringFromIndex(uint nIndex)
{
	return getStringIdStringFromIndex(getMethodNameIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：拿method_id_item数组指定下标的class_idx_字段值
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getMethodClassIdxValueFromIndex(uint nIndex)
{
    STMethodIdItem *pST = getMethodIdSTFromIndex(nIndex);
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
    STMethodIdItem *pST = getMethodIdSTFromIndex(nIndex);
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
    STMethodIdItem *pST = getMethodIdSTFromIndex(nIndex);
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
                getTypeIdStringFromIndex(pST->class_idx_));
        
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
               getTypeIdStringFromIndex(pST->superclass_idx_),
               pST->interfaces_off_, 
               getStringIdStringFromIndex(pST->source_file_idx_),
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
                    getTypeIdStringFromIndex(pSTTI[k].type_idx_));
            }
            printf("\r\n");
        }

        //uint annotations_off
        PSTAnnotationsDirectoryItem pAnnotationsDirectoryItem = NULL;
        if (pST->annotations_off_ != 0)
        {
            pAnnotationsDirectoryItem = (PSTAnnotationsDirectoryItem)
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
        PSTClassDataItem pClassDataItem = NULL;
        if (pST->class_data_off_ != 0)
        {
            pClassDataItem = (PSTClassDataItem)
                ((DWORD)pST->class_data_off_ + getFileBeginAddr());
            int nCount = 0;
            PSTClassDataItem pNew = pClassDataItem;
            //各个数量都是leb128数据表示
            int nstatic_fields_size_ = readLeb128((BYTE*)pNew);
            nCount = getLeb128Size((BYTE*)pNew);
            pNew = (PSTClassDataItem)((DWORD)pNew + nCount);
            int ninstance_fields_size_ = readLeb128((BYTE*)pNew);
            nCount = getLeb128Size((BYTE*)pNew);
            pNew = (PSTClassDataItem)((DWORD)pNew + nCount);
            int ndirect_methods_size_ = readLeb128((BYTE*)pNew);
            nCount = getLeb128Size((BYTE*)pNew);
            pNew = (PSTClassDataItem)((DWORD)pNew + nCount);
            int nvirtual_methods_size_ = readLeb128((BYTE*)pNew);
            nCount = getLeb128Size((BYTE*)pNew);
            pNew = (PSTClassDataItem)((DWORD)pNew + nCount);

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
                    pNew = (PSTClassDataItem)((DWORD)pNew + nCount);
                    
                    //访问标志
                    int naccess_flags = readLeb128((BYTE*)pNew);
                    nCount = getLeb128Size((BYTE*)pNew);
                    pNew = (PSTClassDataItem)((DWORD)pNew + nCount);
                    

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
                    pNew = (PSTClassDataItem)((DWORD)pNew + nCount);
                    
                    //访问标志
                    int naccess_flags = readLeb128((BYTE*)pNew);
                    nCount = getLeb128Size((BYTE*)pNew);
                    pNew = (PSTClassDataItem)((DWORD)pNew + nCount);
                    
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
                    pNew = (PSTClassDataItem)((DWORD)pNew + nCount);
                    
                    int naccess_flags = readLeb128((BYTE*)pNew);
                    nCount = getLeb128Size((BYTE*)pNew);
                    pNew = (PSTClassDataItem)((DWORD)pNew + nCount);
                    
                    int ncode_off = readLeb128((BYTE*)pNew);
                    nCount = getLeb128Size((BYTE*)pNew);
                    pNew = (PSTClassDataItem)((DWORD)pNew + nCount);
                    
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
                        PSTCodeItem pSTCI = (PSTCodeItem)((DWORD)ncode_off + getFileBeginAddr());
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
                    pNew = (PSTClassDataItem)((DWORD)pNew + nCount);
                    
                    int naccess_flags = readLeb128((BYTE*)pNew);
                    nCount = getLeb128Size((BYTE*)pNew);
                    pNew = (PSTClassDataItem)((DWORD)pNew + nCount);
                    
                    int ncode_off = readLeb128((BYTE*)pNew);
                    nCount = getLeb128Size((BYTE*)pNew);
                    pNew = (PSTClassDataItem)((DWORD)pNew + nCount);
                    
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
                        PSTCodeItem pSTCI = (PSTCodeItem)((DWORD)ncode_off + getFileBeginAddr());
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
/* 函数功能：拿类信息列表(ClassDef_list)指定下标的结构指针
 * 函数参数: nIndex 下标
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
	return getTypeIdStringFromIndex(getClassClassIdxValueFromIndex(nIndex));
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
/* 函数功能：返回访问标志字符串，返回值需要手动delete []
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getClassAccessFlagsString(DWORD dwFlags)
{
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
	return getTypeIdStringFromIndex(getClassSuperclassIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取指定下标的ClassDef结构中的source_file_idx_的字符串
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getClassSourceFileIdxStringFromIndex(uint nIndex)
{
	return getStringIdStringFromIndex(getClassSourceFileIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：根据相应Class结构中的class_annotations_off_判断是否需要输出相关信息
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::isClassNeedShowAnnotationsString(uint nIndex)
{
    return getClassAnnotationsOffValueFromIndex(nIndex) != 0;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取相应Class结构中的class_annotations_off_结构数据,返回值需要手动释放
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getClassAnnotationStringFromIndex(uint nIndex)
{
    char *result = new char[MAXBYTE * 4];
    result[0] = '\0';
    sprintf(result, "class_annotations_off_:%X fields_size_:%X "
        "methods_size_:%X parameters_size_:%X",
        getClassAnnotationsClassAnnotationsOffValueFromIndex(nIndex),
        getClassAnnotationsFieldsSizeValueFromIndex(nIndex),
        getClassAnnotationsMethodsSizeValueFromIndex(nIndex),
        getClassAnnotationsParametersSizeValueFromIndex(nIndex));
    return result;
}
//获取指定下标的STAnnotationsDirectoryItem结构指针
PSTAnnotationsDirectoryItem CMyDexObj::getClassAnnotationsDirectoryItemSTFromIndex(uint nIndex)
{
    //获取对应AnnotationsOff字段值
    DWORD dwOff = getClassAnnotationsOffValueFromIndex(nIndex);
	//异常时的处理，指定下标结构的dwOff为空
	if (!dwOff)
	{
		return NULL;
	}

    //这个字段值即为结构在文件的偏移，加上文件起始地址即为这个结构的指针
    PSTAnnotationsDirectoryItem pAnnotationsDirectoryItem = 
        (PSTAnnotationsDirectoryItem)(dwOff + getFileBeginAddr());
    return pAnnotationsDirectoryItem;
}
//获取相应Class结构中的class_annotations_off_结构中class_annotations_off_字段值
uint32_t CMyDexObj::getClassAnnotationsClassAnnotationsOffValueFromIndex(uint nIndex)
{
    PSTAnnotationsDirectoryItem pAnnotationsDirectoryItem = 
        getClassAnnotationsDirectoryItemSTFromIndex(nIndex);
	//如果pAnnotationsDirectoryItem无效则返回0
	if (!pAnnotationsDirectoryItem)
	{
		return 0;
	}
    return pAnnotationsDirectoryItem->class_annotations_off_;
}
//获取相应Class结构中的class_annotations_off_结构中fields_size_字段值
uint32_t CMyDexObj::getClassAnnotationsFieldsSizeValueFromIndex(uint nIndex)
{
    PSTAnnotationsDirectoryItem pAnnotationsDirectoryItem = 
        getClassAnnotationsDirectoryItemSTFromIndex(nIndex);
	//如果pAnnotationsDirectoryItem无效则返回0
	if (!pAnnotationsDirectoryItem)
	{
		return 0;
	}
    return pAnnotationsDirectoryItem->fields_size_;
}
//获取相应Class结构中的class_annotations_off_结构中methods_size_字段值
uint32_t CMyDexObj::getClassAnnotationsMethodsSizeValueFromIndex(uint nIndex)
{
    PSTAnnotationsDirectoryItem pAnnotationsDirectoryItem = 
        getClassAnnotationsDirectoryItemSTFromIndex(nIndex);
	//如果pAnnotationsDirectoryItem无效则返回0
	if (!pAnnotationsDirectoryItem)
	{
		return 0;
	}
    return pAnnotationsDirectoryItem->methods_size_;
}
//获取相应Class结构中的class_annotations_off_结构中parameters_size_字段值
uint32_t CMyDexObj::getClassAnnotationsParametersSizeValueFromIndex(uint nIndex)
{
    PSTAnnotationsDirectoryItem pAnnotationsDirectoryItem = 
        getClassAnnotationsDirectoryItemSTFromIndex(nIndex);
	//如果pAnnotationsDirectoryItem无效则返回0
	if (!pAnnotationsDirectoryItem)
	{
		return 0;
	}
    return pAnnotationsDirectoryItem->parameters_size_;
}    
//根据相应Class结构中的interfaces_off_判断是否需要输出相关信息
bool CMyDexObj::isClassNeedShowInterfacesString(uint nIndex)
{
    PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
    return pCD->interfaces_off_ != 0;
}
//获取相应Class结构中的class_interfaces_off_结构数据,返回值需要手动释放
const char* CMyDexObj::getClassInterfacesStringFromIndex(uint nIndex)
{
    char *result = new char[MAXBYTE * 4];
    result[0] = '\0';
    char temp[MAXBYTE];
    //获取list_结构数量
    DWORD dwSize = getClassInterfaceListSizeFromIndex(nIndex);
    //获取list_结构起始地址
    PSTTypeItemList pTL = getClassInterfaceListSTFileOffsetFromIndex(nIndex);
	/*  此时的pTL结构为
		// Raw type_list. 
		typedef struct TypeList {
			uint32_t size_;             //指示其后list实际Item数量
			TypeItem list_[1];          //TypeItem数组
		} STTypeList, *PSTTypeList;
	*/
	//如果interfaces_off_数据有问题则不进行遍历收集
	if (!dwSize || !pTL)
	{
		return result;
	}
	//由于上面的pTL是一个文件偏移，所以加上首地址
	pTL = (PSTTypeItemList)(DWORD(pTL) + getFileBeginAddr());
    //list_地址强转为TypeItem，取其内容即为基于type_ids的下标
    PSTTypeItem pTI = (PSTTypeItem)&pTL->list_;
    sprintf(result, "interfaces Size:%d", dwSize);
    for (DWORD i = 0; i < dwSize; i++)
    {
        sprintf(temp, " (%X)%s", 
            pTI->type_idx_,
            getTypeIdStringFromIndex(pTI->type_idx_));
        strcat(result, temp);
    }
    return result;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取指定Class下标的interfaces_off_字段指向的type_item_list结构在文件中的偏移
 * 函数参数: nIndex class_ids目标下标
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
PSTTypeItemList CMyDexObj::getClassInterfaceListSTFileOffsetFromIndex(uint nIndex)  
{
    //获取ClassDef->interfaces_off_字段值
    DWORD dwOff = getClassInterfaceOffValueFromIndex(nIndex);
	//如果interfaces_off_字段值为空则返回空
	if (!dwOff)
	{
		return NULL;
	}
    //+文件起始地址即为结构地址
    PSTTypeItemList pTL = (PSTTypeItemList)
        (dwOff);
    return pTL;
}
//获取指定Class下标的interfaces_off_结构下的list_结构数量
uint32_t CMyDexObj::getClassInterfaceListSizeFromIndex(uint nIndex)
{
	//拿偏移
    PSTTypeItemList pTL = getClassInterfaceListSTFileOffsetFromIndex(nIndex);
	//如果没有interfaces_off_数据会返回空，规避下
	if (!pTL)
	{
		return 0;
	}
	//加首地址
	pTL = (PSTTypeItemList)((DWORD)pTL + getFileBeginAddr());
    return pTL->size_;
}
//根据class_def_item->class_data_off_字段值判断是否需要输出
bool CMyDexObj::isClassNeedShowClassDataString(uint nIndex)
{
	//对应class_data_off_字段值不为0则可以输出
    return getClassClassDataOffValueFromIndex(nIndex) != 0;
}
//获取相应Class结构中的class_data_off_结构数据,返回值需要手动释放
const char* CMyDexObj::getClassClassDataStringFromIndex(uint nIndex)
{
	char * result = new char[MAXBYTE];
	result[0] = '\0';
	sprintf(result, 
			"static_fields_size_:%x instance_fields_size_:%d "
			"direct_methods_size_:%d virtual_methods_size_:%d",
			getClassClassDataStaticFieldsSizeValueFromIndex(nIndex),
			getClassClassDataInstanceFieldsSizeValueFromIndex(nIndex),
			getClassClassDataDirectMethodsSizeValueFromIndex(nIndex),
			getClassClassDataVirtualMethodsSizeValueFromIndex(nIndex));
	return result;
}
//获取指定Class结构中的STClassDataItem结构指定
PSTClassDataItem CMyDexObj::getClassClassDataSTFromIndex(uint nIndex)
{
	DWORD dwOff = getClassClassDataOffValueFromIndex(nIndex);
	if(dwOff == 0)
		return NULL;
	PSTClassDataItem pCD = (PSTClassDataItem)(dwOff + getFileBeginAddr());
	return pCD;
}
//获取指定class_def_item->class_data_off_->static_fields_size字段值，这是LEB128类型数据
uint32_t CMyDexObj::getClassClassDataStaticFieldsSizeValueFromIndex(uint nIndex)
{
	//获取对应class_def_item->class_data_off_指向的结构指针，
	PSTClassDataItem pCDI = getClassClassDataSTFromIndex(nIndex);
	//注意这里当off为0时返回为空，需要特殊处理一下
	if(pCDI == NULL)
		return 0;
	BYTE *pByte = (BYTE*)pCDI;
	//第一个LEB128数据是static_fields_size字段
	uint32_t nStaticFieldSizeValue = readLeb128(pByte);
	uint nSize = getLeb128Size(pByte);
	return nStaticFieldSizeValue;
}
//获取指定class_def_item->class_data_off_->instance_fields_size字段值，这是LEB128类型数据
uint32_t CMyDexObj::getClassClassDataInstanceFieldsSizeValueFromIndex(uint nIndex)
{
	//第一个LEB128数据是static_fields_size字段
	PSTClassDataItem pCDI = getClassClassDataSTFromIndex(nIndex);
	//返回为空即没有这个类型的数据
	if (pCDI == 0)
	{
		return 0;
	}
	BYTE *pByte = (BYTE*)pCDI;
	uint32_t nStaticFieldSizeValue = readLeb128(pByte);
	uint nSize = getLeb128Size(pByte);
	//第二个LEB128数据是instance_fields_size字段
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	uint32_t nInstanceFieldSizeValue = readLeb128(pByte);
	nSize = getLeb128Size(pByte);
	return nInstanceFieldSizeValue;
}
//获取指定class_def_item->class_data_off_->direct_methods_size字段值，这是LEB128类型数据
uint32_t CMyDexObj::getClassClassDataDirectMethodsSizeValueFromIndex(uint nIndex)
{
	//第一个LEB128数据是direct_methods_size字段
	PSTClassDataItem pCDI = getClassClassDataSTFromIndex(nIndex);
	if (pCDI == NULL)
	{
		return 0;
	}
	BYTE *pByte = (BYTE*)pCDI;
	uint32_t nStaticFieldSizeValue = readLeb128(pByte);
	uint nSize = getLeb128Size(pByte);
	//第二个LEB128数据是instance_fields_size字段
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	uint32_t nInstanceFieldSizeValue = readLeb128(pByte);
	nSize = getLeb128Size(pByte);
	//第三个LEB128数据是direct_methods_size字段
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	uint32_t nDirectMethodsSizeValue = readLeb128(pByte);
	nSize = getLeb128Size(pByte);
	return nDirectMethodsSizeValue;
}
//获取指定class_def_item->class_data_off_->virtual_methods_size字段值，
//这是LEB128类型数据表示这个类含有的virtual_method数量
uint32_t CMyDexObj::getClassClassDataVirtualMethodsSizeValueFromIndex(uint nIndex)
{
	//第一个LEB128数据是static_fields_size字段
	PSTClassDataItem pCDI = getClassClassDataSTFromIndex(nIndex);
	if (pCDI == NULL)
	{
		return 0;
	}
	BYTE *pByte = (BYTE*)pCDI;
	uint32_t nStaticFieldSizeValue = readLeb128(pByte);
	uint nSize = getLeb128Size(pByte);
	//第二个LEB128数据是instance_fields_size字段
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	uint32_t nInstanceFieldSizeValue = readLeb128(pByte);
	nSize = getLeb128Size(pByte);
	//第三个LEB128数据是direct_methods_size字段
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	uint32_t nDirectMethodsSizeValue = readLeb128(pByte);
	nSize = getLeb128Size(pByte);
	//第四个LEB128数据是virtual_methods_size字段
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	uint32_t nVirtualMethodsSizeValue = readLeb128(pByte);
	nSize = getLeb128Size(pByte);
	return nVirtualMethodsSizeValue;
}
//获取指定class_def_item->class_data_off_->static_fields_size字段实际占用的字节长度
uint32_t CMyDexObj::getClassClassDataStaticFieldsSizeLenFromIndex(uint nIndex)
{
	//第一个LEB128数据是static_fields_size字段
	PSTClassDataItem pCDI = getClassClassDataSTFromIndex(nIndex);
	BYTE *pByte = (BYTE*)pCDI;
	uint nSize = getLeb128Size(pByte);
	return nSize;
}
//获取指定class_def_item->class_data_off_->instance_fields_size字段实际占用的字节长度
uint32_t CMyDexObj::getClassClassDataInstanceFieldsSizeLenFromIndex(uint nIndex)
{
	//第一个LEB128数据是static_fields_size字段
	PSTClassDataItem pCDI = getClassClassDataSTFromIndex(nIndex);
	BYTE *pByte = (BYTE*)pCDI;
	uint nSize = getLeb128Size(pByte);
	//第二个LEB128数据是instance_fields_size字段
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	nSize = getLeb128Size(pByte);
	return nSize;
}
//获取指定class_def_item->class_data_off_->direct_methods_size字段实际占用的字节长度
uint32_t CMyDexObj::getClassClassDataDirectMethodsSizeLenFromIndex(uint nIndex)
{
	//第一个LEB128数据是static_fields_size字段
	PSTClassDataItem pCDI = getClassClassDataSTFromIndex(nIndex);
	BYTE *pByte = (BYTE*)pCDI;
	uint nSize = getLeb128Size(pByte);
	//第二个LEB128数据是instance_fields_size字段
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	nSize = getLeb128Size(pByte);
	//第三个LEB128数据是direct_methods_size字段
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	nSize = getLeb128Size(pByte);
	return nSize;
}
//获取指定class_def_item->class_data_off_->virtual_methods_size字段实际占用的字节长度
uint32_t CMyDexObj::getClassClassDataVirtualMethodsSizeLenFromIndex(uint nIndex)
{
	//第一个LEB128数据是static_fields_size字段
	PSTClassDataItem pCDI = getClassClassDataSTFromIndex(nIndex);
	if (pCDI == NULL)
	{
		return 0;
	}
	BYTE *pByte = (BYTE*)pCDI;
	uint nSize = getLeb128Size(pByte);
	//第二个LEB128数据是instance_fields_size字段
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	nSize = getLeb128Size(pByte);
	//第三个LEB128数据是direct_methods_size字段
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	nSize = getLeb128Size(pByte);
	//第四个LEB128数据是virtual_methods_size字段
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	nSize = getLeb128Size(pByte);
	return nSize;
}
//获取class_def_item->class_data_off_各字段数量指定后的首地址，其依次为实际数据的属性
BYTE *CMyDexObj::getClassClassDataAttributeAddrFromIndex(uint nIndex)
{
	//第一个LEB128数据是static_fields_size字段
	PSTClassDataItem pCDI = getClassClassDataSTFromIndex(nIndex);
	BYTE *pByte = (BYTE*)pCDI;
	uint nSize = getLeb128Size(pByte);
	//第二个LEB128数据是instance_fields_size字段
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	nSize = getLeb128Size(pByte);
	//第三个LEB128数据是direct_methods_size字段
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	nSize = getLeb128Size(pByte);
	//第四个LEB128数据是virtual_methods_size字段
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	nSize = getLeb128Size(pByte);
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	return pByte;
}
//指定class_def_item->class_data_off_->static_fields_size字段值是否为0
bool CMyDexObj::isClassNeedShowStaticFieldsStringFromIndex(uint nIndex)
{
	uint32_t nSize = getClassClassDataStaticFieldsSizeValueFromIndex(nIndex);
	return nSize != 0;
}
/*
 * 获取指定class_def_item->class_data_off_->static_fields_size字段的字符串,返回值需要手动释放
 * 返回的数据形式："[%d]method_idx_diff:%X access_flags:%X"
 *
 */
const char* CMyDexObj::getClassStaticFieldsStringFromIndex(uint nIndex, uint nFieldIndex)
{
	char *result = new char[MAXBYTE * 4];
	result[0] = '\0';
	//获取class_data_off_地址加上文件起始得到4个leb128 size的地址
	PSTClassDataItem pCDI = getClassClassDataSTFromIndex(nIndex);
	//隔开4个leb128数据长度即为属性首地址
	BYTE *pByte = getNextSTAddr((BYTE*)pCDI, 4);
	//获取static_fields_size_字段值，即其个数
	uint nstatic_fields_size = getClassClassDataStaticFieldsSizeValueFromIndex(nIndex);
	//避免万一，当该字段为0时不作遍历
	if (nstatic_fields_size == 0 || nFieldIndex < 0 || nFieldIndex > nstatic_fields_size)
	{
		return result;
	}
	//目标字段条件符合预期时进行遍历
	for (uint i = 0; i < nstatic_fields_size; i++)
	{
		if (i == nFieldIndex)
		{
			sprintf(result, "[%d]method_idx_diff:%X access_flags:%X", 
				i,
				getClassStaticFieldsFieldIdxDiffValueIndex(pByte),
				getClassStaticFieldsAccessFlagsValueIndex(pByte));
			break;
		}
		//每一个fields占两个leb128类型
		pByte = getNextSTAddr(pByte);
	}
	return result;
}
//获取指定class_def_item->class_data_off_->static_fields->field_idx_diff字段值,这是一个LEB128数据
DWORD CMyDexObj::getClassStaticFieldsFieldIdxDiffValueIndex(BYTE *pByte)
{
	//第一个leb128数据为field_idx_diff字段值
	int nfield_idx_diff = readLeb128(pByte);
	int nSize = getLeb128Size(pByte);
	return nfield_idx_diff;
}
//获取指定class_def_item->class_data_off_->static_fields->access_flags字段值,这是一个LEB128数据
DWORD CMyDexObj::getClassStaticFieldsAccessFlagsValueIndex(BYTE *pByte)
{
	//第一个leb128数据为field_idx_diff字段值
	int nfield_idx_diff = readLeb128(pByte);
	int nSize = getLeb128Size(pByte);
	//紧跟着的leb128数据为access_flags字段值
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	int naccess_flags = readLeb128(pByte);
	nSize = getLeb128Size(pByte);
	return naccess_flags;
}
//获取下一个FieldST的BYTE地址，默认2个LEB128数据为界
BYTE* CMyDexObj::getNextSTAddr(BYTE *pByte, int nLeb128Count)
{
	int nSize = 0;
	//依次获取leb128长度，加上指针返回
	for (int i = 0; i < nLeb128Count; i++)
	{
		nSize = getLeb128Size(pByte);
		pByte = (BYTE *)(DWORD(pByte) + nSize);
	}
	return pByte;
}

//指定class_def_item->class_data_off_->instance_fields_size字段值是否为0
bool CMyDexObj::isClassNeedShowInstanceFieldsStringFromIndex(uint nIndex)
{
	uint32_t nSize = getClassClassDataInstanceFieldsSizeValueFromIndex(nIndex);
	return nSize != 0;
}
//获取指定class_def_item->class_data_off_->instance_fields_size字段的字符串,返回值需要手动释放
const char* CMyDexObj::getClassInstanceFieldsStringFromIndex(uint nIndex, uint nFieldIndex)
{
	char *result = new char[MAXBYTE * 4];
	result[0] = '\0';
	//获取static_fields_size_字段值，即其个数
	uint nstatic_fields_size = getClassClassDataInstanceFieldsSizeValueFromIndex(nIndex);
	//避免万一，当该字段为0时不作遍历
	if (nstatic_fields_size == 0 || nFieldIndex < 0 || nFieldIndex > nstatic_fields_size)
	{
		return result;
	}
	//获取instance_fields_size对应的结构首地址
	BYTE *pByte = getClassInstanceFieldsAddrFromIndex(nIndex);
	//目标字段条件符合预期时进行遍历
	for (uint i = 0; i < nstatic_fields_size; i++)
	{
		if (i == nFieldIndex)
		{
			sprintf(result, "[%d]method_idx_diff:%X access_flags:%X", 
				i,
				getClassStaticFieldsFieldIdxDiffValueIndex(pByte),
				getClassStaticFieldsAccessFlagsValueIndex(pByte));
			break;
		}
		//每一个fields占两个leb128类型
		pByte = getNextSTAddr(pByte);
	}
	return result;
}
//获取指定class_def_item->class_data_off_->instance_fields_size->field_idx_diff字段值,这是一个LEB128数据
DWORD CMyDexObj::getClassInstanceFieldsFieldIdxDiffValueIndex(BYTE *pByte)
{
	//第一个leb128数据为field_idx_diff字段值
	int nfield_idx_diff = readLeb128(pByte);
	int nSize = getLeb128Size(pByte);
	return nfield_idx_diff;
}
//获取指定class_def_item->class_data_off_->instance_fields_size->access_flags字段值,这是一个LEB128数据
DWORD CMyDexObj::getClassInstanceFieldsAccessFlagsValueIndex(BYTE *pByte)
{
	//第一个leb128数据为field_idx_diff字段值
	int nfield_idx_diff = readLeb128(pByte);
	int nSize = getLeb128Size(pByte);
	//紧跟着的leb128数据为access_flags字段值
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	int naccess_flags = readLeb128(pByte);
	nSize = getLeb128Size(pByte);
	return naccess_flags;
}
//获取指定class_def_item->class_data_off_->instance_fields指向的数据地址,没有则返回空指针！！！
BYTE* CMyDexObj::getClassInstanceFieldsAddrFromIndex(uint nIndex)
{
	//意外处理
	uint nSize = getClassClassDataInstanceFieldsSizeValueFromIndex(nIndex);
	if (nSize == 0)
	{
		return NULL;
	}
	//首先拿这个Class的地址
	PSTClassDataItem pCDI = getClassClassDataSTFromIndex(nIndex);
	//跳过4个leb表示的各个字段的数量
	BYTE *pByte = getNextSTAddr((BYTE*)pCDI, 4);
	//看下前面有几个static_fields数据
	nSize = getClassClassDataStaticFieldsSizeValueFromIndex(nIndex);
	//每个static_fields结构都是两个LEB128数据，所以跳过nSize*2个LEB数据就对了
	pByte = getNextSTAddr(pByte, nSize * 2);
	return pByte;
}

//指定class_def_item->class_data_off_->direct_methods_size字段值是否为0
bool CMyDexObj::isClassNeedShowDirectMethodsStringFromIndex(uint nIndex)
{
	uint32_t nSize = getClassClassDataDirectMethodsSizeValueFromIndex(nIndex);
	return nSize != 0;
}
//获取指定class_def_item->class_data_off_->direct_methods_size字段的字符串,返回值需要手动释放
const char* CMyDexObj::getClassDirectMethodsStringFromIndex(uint nIndex, uint nFieldIndex)
{
	char *result = new char[MAXBYTE * 4];
	result[0] = '\0';
	//获取direct_method_size_字段值，即其个数
	uint ndirect_method_size = getClassClassDataDirectMethodsSizeValueFromIndex(nIndex);
	//避免万一，当该字段为0时不作遍历
	if (ndirect_method_size == 0 || nFieldIndex < 0 || nFieldIndex > ndirect_method_size)
	{
		return result;
	}
	//获取direct_methods_size对应的结构首地址
	BYTE *pByte = getClassDirectMethodsAddrFromIndex(nIndex);
	//目标字段条件符合预期时进行遍历
	for (uint i = 0; i < ndirect_method_size; i++)
	{
		if (i == nFieldIndex)
		{
			sprintf(result, "[%d]method_idx_diff:%X access_flags:%X code_off:%X", 
				i,
				getClassDirectMethodsMethodIdxDiffValueIndex(pByte),
				getClassDirectMethodsAccessFlagsValueIndex(pByte),
				getClassDirectMethodsCodeOffValueIndex(pByte));
			break;
		}
		//每一个fields占3个leb128类型
		pByte = getNextSTAddr(pByte, 3);
	}
	return result;
}
//获取指定class_def_item->class_data_off_->direct_methods_size->field_idx_diff字段值,这是一个LEB128数据
DWORD CMyDexObj::getClassDirectMethodsMethodIdxDiffValueIndex(BYTE *pByte)
{
	//第一个leb128数据为method_idx_diff字段值
	int nfield_idx_diff = readLeb128(pByte);
	int nSize = getLeb128Size(pByte);
	return nfield_idx_diff;
}
//获取指定class_def_item->class_data_off_->direct_methods_size->access_flags字段值,这是一个LEB128数据
DWORD CMyDexObj::getClassDirectMethodsAccessFlagsValueIndex(BYTE *pByte)
{
	//第一个leb128数据为method_idx_diff字段值
	int nfield_idx_diff = readLeb128(pByte);
	int nSize = getLeb128Size(pByte);
	//紧跟着的leb128数据为access_flags字段值
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	int naccess_flags = readLeb128(pByte);
	nSize = getLeb128Size(pByte);
	return naccess_flags;
}
//获取指定class_def_item->class_data_off_->direct_methods_size->code_off字段值,这是一个LEB128数据
DWORD CMyDexObj::getClassDirectMethodsCodeOffValueIndex(BYTE *pByte)
{
	//第一个leb128数据为method_idx_diff字段值
	int nfield_idx_diff = readLeb128(pByte);
	int nSize = getLeb128Size(pByte);
	//紧跟着的leb128数据为access_flags字段值
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	int naccess_flags = readLeb128(pByte);
	nSize = getLeb128Size(pByte);
	//紧跟着的leb128数据为code_off字段值
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	int ncode_off = readLeb128(pByte);
	nSize = getLeb128Size(pByte);
	return ncode_off;
}
//获取指定class_def_item->class_data_off_->direct_methods_size->code_off字段值,这是一个LEB128数据
DWORD CMyDexObj::getClassDirectMethodsCodeOffValueIndex(uint nIndex, uint nFieldIndex)
{
    //获取direct_method_size_字段值，即其个数
    uint ndirect_method_size = getClassClassDataDirectMethodsSizeValueFromIndex(nIndex);
    //避免万一，当该字段为0时不作遍历
    if (ndirect_method_size == 0 || nFieldIndex < 0 || nFieldIndex > ndirect_method_size)
    {
        return 0;
    }
    //获取virtual_methods_size对应的结构首地址,三个leb128数据分别表示methods_idx_diff,access_flags,code_off
    BYTE *pByte = getClassDirectMethodsAddrFromIndex(nIndex);
    //目标字段条件符合预期时进行遍历
    for (uint i = 0; i < ndirect_method_size; i++)
    {
        if (i == nFieldIndex)
        {
            return getClassDirectMethodsCodeOffValueIndex(pByte);
        }
        //每一个fields占3个leb128类型
        pByte = getNextSTAddr(pByte, 3);
    }
    return 0;
}
//获取指定class_def_item->class_data_off_->direct_methods_size指向的数据地址,没有则返回空指针！！！
BYTE* CMyDexObj::getClassDirectMethodsAddrFromIndex(uint nIndex)
{
	//意外处理
	uint nSize = getClassClassDataDirectMethodsSizeValueFromIndex(nIndex);
	if (nSize == 0)
	{
		return NULL;
	}
	//首先拿这个Class的地址
	PSTClassDataItem pCDI = getClassClassDataSTFromIndex(nIndex);
	//跳过4个leb表示的各个字段的数量
	BYTE *pByte = getNextSTAddr((BYTE*)pCDI, 4);
	//看下前面有几个static_fields数据
	nSize = getClassClassDataStaticFieldsSizeValueFromIndex(nIndex);
	//看下前面有几个instance_fields数据
	nSize += getClassClassDataInstanceFieldsSizeValueFromIndex(nIndex);
	//每个static_fields结构都是两个LEB128数据，所以跳过nSize*2个LEB数据就对了
	pByte = getNextSTAddr(pByte, nSize * 2);
	return pByte;
}
//获取指定class_def_item->class_data_off_->direct_methods_size->data_off_是否需要输出
bool CMyDexObj::isClassDirectMethodsNeedShowDataOffStringFromIndex(uint nIndex)
{
    //获取指定下标下的class_def_item->class_data_off_->direct_methods_size对应的首地址
    BYTE *pByte = getClassDirectMethodsAddrFromIndex(nIndex); //getClassVirtualMethodsAddrFromIndex
    if(pByte == NULL)
        return false;
    
    //对应结构off不为0表示数据有效
    DWORD dwOff = getClassDirectMethodsCodeOffValueIndex(pByte);
    return dwOff != 0;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取指定类下标指定DirectMethod的字节码
 * 函数参数: nClassIndex nDirectMethodIndex
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getClassDirectMethodsDataOffStringFromIndex(uint nClassIndex, uint nDirectMethodIndex)
{
	DWORD dwOff = getClassDirectMethodsCodeOffValueIndex(nClassIndex, nDirectMethodIndex);
	return getClassDirectMethodsDataOffStringFromIndex(dwOff);
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取指定class_def_item->class_data_off_->direct_methods_size->data_off_字节码
                返回值需要手动释放delete[] 
 * 函数参数: 
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getClassDirectMethodsDataOffStringFromIndex(DWORD dwOff)
{
    char *result = new char[MAXBYTE * 4];
    result[0] = '\0';
    sprintf(result, "registers_size:%d ins_size:%d "
        "outs_size:%d tries_size:%d "
        "debug_info_off:%X insns_size_in_code_units:%d "
        "insns(FileOffsetOfMachineCode):%X",
        getClassDirectMethodsDataOffRegisterSizeValueFromIndex(dwOff),
        getClassDirectMethodsDataOffInsSizeValueFromIndex(dwOff),
        getClassDirectMethodsDataOffOutsSizeValueFromIndex(dwOff),
        getClassDirectMethodsDataOffTriesSizeValueFromIndex(dwOff),
        getClassDirectMethodsDataOffDebugInfoOffValueFromIndex(dwOff),
        getClassDirectMethodsDataOffInsnsSizeInCodeUnitsValueFromIndex(dwOff),
        getClassDirectMethodsDataOffInsnsFileOffsetFromIndex(dwOff)
        );
    return result;
}
//获取data_off_结构下的register_size_字段值
uint16_t CMyDexObj::getClassDirectMethodsDataOffRegisterSizeValueFromIndex(DWORD dwOff)
{
    return getClassVirtualMethodsDataOffRegisterSizeValueFromIndex(dwOff);
}
//获取data_off_结构下的ins_size_字段值
uint16_t CMyDexObj::getClassDirectMethodsDataOffInsSizeValueFromIndex(DWORD dwOff)
{
    return getClassVirtualMethodsDataOffInsSizeValueFromIndex(dwOff);
}
//获取data_off_结构下的out_size_字段值
uint16_t CMyDexObj::getClassDirectMethodsDataOffOutsSizeValueFromIndex(DWORD dwOff)
{
    return getClassVirtualMethodsDataOffOutsSizeValueFromIndex(dwOff);
}
//获取data_off_结构下的tries_size_字段值
uint16_t CMyDexObj::getClassDirectMethodsDataOffTriesSizeValueFromIndex(DWORD dwOff)
{
    return getClassVirtualMethodsDataOffTriesSizeValueFromIndex(dwOff);
}
//获取data_off_结构下的debug_info_off_字段值
uint32_t CMyDexObj::getClassDirectMethodsDataOffDebugInfoOffValueFromIndex(DWORD dwOff)
{
    return getClassVirtualMethodsDataOffDebugInfoOffValueFromIndex(dwOff);
}
//获取data_off_结构下的insns数据大小，实际是WORD的个数
uint32_t CMyDexObj::getClassDirectMethodsDataOffInsnsSizeInCodeUnitsValueFromIndex(DWORD dwOff)
{
    return getClassVirtualMethodsDataOffInsnsSizeInCodeUnitsValueFromIndex(dwOff);
}
//获取data_off_结构下的insns数据起始地址
WORD* CMyDexObj::getClassDirectMethodsDataOffInsnsFileOffsetFromIndex(DWORD dwOff)
{
    return getClassVirtualMethodsDataOffInsnsFileOffsetFromIndex(dwOff);
}

//获取ClassDirectMethodsDataOffInsns下的机器码，返回值手动释放
const char* CMyDexObj::getClassDirectMethodsDataOffInsnsMachineCode(uint nClassIndex, uint nDirectMethodIndex)
{
	//获取指定类下的指定下标DirectMethodsCodeOff字段值，传这个文件偏移由getClassDirectMethodsDataOffInsnsMachineCode函数去获取
	DWORD dwOff = getClassDirectMethodsCodeOffValueIndex(nClassIndex, nDirectMethodIndex);
	return getClassDirectMethodsDataOffInsnsMachineCode((PSTCodeItem)dwOff);
}
//获取ClassDirectMethodsDataOffInsns下的机器码，返回值手动释放
//pSTCI pSTCIFileOffset
const char* CMyDexObj::getClassDirectMethodsDataOffInsnsMachineCode(PSTCodeItem pSTCI)
{
    if (!pSTCI)
    {
		char *result = new char[1];
        return result;
    }
	pSTCI = (PSTCodeItem)((DWORD)pSTCI + getFileBeginAddr());
	uint32_t dwSize = pSTCI->insns_size_in_code_units_;
	//" %02X %02X"
    char *result = new char[dwSize * 6 + 1];
	result[0] = '\0';
    char temp[MAXBYTE];
	
    if(dwSize != 0)
    {
        for (uint32_t i = 0; i < dwSize;
        i++)
        {
            //2个字节读出
            uint16_t code = pSTCI->insns_[i];
            
            sprintf(temp, " %02X %02X", (BYTE)(code & 0xff),
                (BYTE)((code >> 8) & 0xff));
            strcat(result, temp);
        }
	}
    return result;
}

//指定class_def_item->class_data_off_->virtual_methods_size字段值是否为0
bool CMyDexObj::isClassNeedShowVirtualMethodsStringFromIndex(uint nIndex)
{
	uint32_t nSize = getClassClassDataVirtualMethodsSizeValueFromIndex(nIndex);
	return nSize != 0;
}
//获取指定class_def_item->class_data_off_->virtual_methods_size字段的字符串,返回值需要手动释放
const char* CMyDexObj::getClassVirtualMethodsStringFromIndex(uint nIndex, uint nFieldIndex)
{
	char *result = new char[MAXBYTE * 4];
	result[0] = '\0';
	//获取direct_method_size_字段值，即其个数
	uint nvirtual_method_size = getClassClassDataVirtualMethodsSizeValueFromIndex(nIndex);
	//避免万一，当该字段为0时不作遍历
	if (nvirtual_method_size == 0 || nFieldIndex < 0 || nFieldIndex > nvirtual_method_size)
	{
		return result;
	}
	//获取virtual_methods_size对应的结构首地址
	BYTE *pByte = getClassVirtualMethodsAddrFromIndex(nIndex);
	//目标字段条件符合预期时进行遍历
	for (uint i = 0; i < nvirtual_method_size; i++)
	{
		if (i == nFieldIndex)
		{
			DWORD dwFlags = getClassVirtualMethodsAccessFlagsValueIndex(pByte);
// 			sprintf(result, "[%d]method_idx_diff:%X access_flags:%X code_off:%X", 
// 				i,
// 				getClassVirtualMethodsFieldIdxDiffValueIndex(pByte),
// 				dwFlags,
// 				getClassVirtualMethodsCodeOffValueIndex(pByte));
			const char* p = getClassAccessFlagsString(dwFlags);
			sprintf(result, "[%d]method_idx_diff:%X access_flags:%s code_off:%X", 
				i,
				getClassVirtualMethodsFieldIdxDiffValueIndex(pByte),
				p,
				getClassVirtualMethodsCodeOffValueIndex(pByte));
			delete[] (char*)p;
			break;
		}
		//每一个fields占3个leb128类型
		pByte = getNextSTAddr(pByte, 3);
	}
	return result;
}
//获取指定class_def_item->class_data_off_->virtual_methods_size->field_idx_diff字段值,这是一个LEB128数据
DWORD CMyDexObj::getClassVirtualMethodsFieldIdxDiffValueIndex(BYTE *pByte)
{
	return getClassDirectMethodsMethodIdxDiffValueIndex(pByte);
}
//获取指定class_def_item->class_data_off_->virtual_methods_size->access_flags字段值,这是一个LEB128数据
DWORD CMyDexObj::getClassVirtualMethodsAccessFlagsValueIndex(BYTE *pByte)
{
	return getClassDirectMethodsAccessFlagsValueIndex(pByte);
}
//获取指定class_def_item->class_data_off_->virtual_methods_size->code_off字段值,这是一个LEB128数据
DWORD CMyDexObj::getClassVirtualMethodsCodeOffValueIndex(BYTE *pByte)
{
	return getClassDirectMethodsCodeOffValueIndex(pByte);
}
//获取指定class_def_item[nIndex]->class_data_off_->virtual_methods_size[nVirtualIndex]->code_off字段值,
//这是一个LEB128数据，指定CodeItem结构在文件中的偏移
DWORD CMyDexObj::getClassVirtualMethodsCodeOffValueFromIndex(uint nIndex, uint nVirtualIndex)
{
    //获取virtual_method_size_字段值，即其个数
    uint nvirtual_method_size = getClassClassDataVirtualMethodsSizeValueFromIndex(nIndex);
    //避免万一，当该字段为0时不作遍历
    if (nvirtual_method_size == 0 || nVirtualIndex < 0 || nVirtualIndex > nvirtual_method_size)
    {
        return 0;
    }
    //获取virtual_methods_size对应的结构首地址,三个leb128数据分别表示methods_idx_diff,access_flags,code_off
    BYTE *pByte = getClassVirtualMethodsAddrFromIndex(nIndex);
    //目标字段条件符合预期时进行遍历
    for (uint i = 0; i < nvirtual_method_size; i++)
    {
        if (i == nVirtualIndex)
        {
            return getClassVirtualMethodsCodeOffValueIndex(pByte);
        }
        //每一个fields占3个leb128类型
        pByte = getNextSTAddr(pByte, 3);
    }
	return 0;
}
//获取指定class_def_item->class_data_off_->virtual_methods_size指向的数据地址,没有则返回空指针！！！
BYTE* CMyDexObj::getClassVirtualMethodsAddrFromIndex(uint nIndex)
{
	//意外处理
	uint nSize = getClassClassDataVirtualMethodsSizeValueFromIndex(nIndex);
	if (nSize == 0)
	{
		return NULL;
	}
	//首先拿这个Class的地址
	PSTClassDataItem pCDI = getClassClassDataSTFromIndex(nIndex);
	//跳过4个leb表示的各个字段的数量
	BYTE *pByte = getNextSTAddr((BYTE*)pCDI, 4);
	//看下前面有几个static_fields数据,每个static_fields结构都是两个LEB128数据
	nSize = getClassClassDataStaticFieldsSizeValueFromIndex(nIndex) * 2;
	//看下前面有几个instance_fields数据每个static_fields结构都是两个LEB128数据
	nSize += getClassClassDataInstanceFieldsSizeValueFromIndex(nIndex) * 2;
	//看下前面有几个direct_method_fields数据每个static_fields结构都是三个LEB128数据，
	nSize += getClassClassDataDirectMethodsSizeValueFromIndex(nIndex) * 3;
	//所以跳过LEB数据就对了
	pByte = getNextSTAddr(pByte, nSize);
	return pByte;
}
//获取指定class_def_item->class_data_off_->virtual_methods_size->data_off_是否需要输出
bool CMyDexObj::isClassVirturlMethodsNeedShowDataOffStringFromIndex(uint nIndex)
{
    //获取指定下标下的class_def_item->class_data_off_->virtual_methods_size对应的首地址
    BYTE *pByte = getClassVirtualMethodsAddrFromIndex(nIndex);
    if(pByte == NULL)
        return false;

    //对应结构off不为0表示数据有效
    DWORD dwOff = getClassVirtualMethodsCodeOffValueIndex(pByte);
    return dwOff != 0;
}
//获取指定class_def_item->class_data_off_->virtual_methods_size->data_off_指向结构首地址
PSTCodeItem CMyDexObj::getClassVirtualMethodsDataOffSTFromeIndex(uint nIndex)
{
    //获取指定下标下的class_def_item->class_data_off_->virtual_methods_size对应的首地址
    PSTCodeItem pCI = (PSTCodeItem)getClassVirtualMethodsAddrFromIndex(nIndex); 
    return pCI;
}
///////////////////////////////////////////////////////////////////////////
/* 函数功能：获取指定data_off_字段指向的方法信息字符串，返回值需要手动释放delete[]                 
 * 函数参数: dwOff CodeItem的文件偏移
 * 函数返回值：
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getClassVirtualMethodsDataOffStringFromIndex(DWORD dwOff)
{
    char *result = new char[MAXBYTE * 4];
    result[0] = '\0';
    sprintf(result, "registers_size:%d ins_size:%d "
        "outs_size:%d tries_size:%d "
        "debug_info_off:%X insns_size_in_code_units:%d "
		"insns:%X",
        getClassVirtualMethodsDataOffRegisterSizeValueFromIndex(dwOff),
        getClassVirtualMethodsDataOffInsSizeValueFromIndex(dwOff),
        getClassVirtualMethodsDataOffOutsSizeValueFromIndex(dwOff),
        getClassVirtualMethodsDataOffTriesSizeValueFromIndex(dwOff),
        getClassVirtualMethodsDataOffDebugInfoOffValueFromIndex(dwOff),
        getClassVirtualMethodsDataOffInsnsSizeInCodeUnitsValueFromIndex(dwOff),
		getClassVirtualMethodsDataOffInsnsFileOffsetFromIndex(dwOff)
        );
    return result;
}
//获取指定class_def_item指定virtual_methods下的data_off_字段指向的方法信息字符串，返回值需要手动释放delete[]   
const char* CMyDexObj::getClassVirtualMethodsDataOffStringFromIndex(uint nIndex, uint nVirtualMethodIndex)
{
	//读取对应类下的指定VirtualMethod结构下的code_off值，其即为CodeItem结构的文件偏移
	DWORD dwOff = getClassVirtualMethodsCodeOffValueFromIndex(nIndex, nVirtualMethodIndex);
	return getClassVirtualMethodsDataOffStringFromIndex(dwOff);
}
//获取data_off_结构下的register_size_字段值
uint16_t CMyDexObj::getClassVirtualMethodsDataOffRegisterSizeValueFromIndex(DWORD dwOff)
{
	//如果传入的参数为0，则返回0
	if (dwOff == 0)
	{
		return 0;
	}
    PSTCodeItem pCI = (PSTCodeItem)(dwOff + getFileBeginAddr());
    return pCI->registers_size_;
}
//获取data_off_结构下的ins_size_字段值
uint16_t CMyDexObj::getClassVirtualMethodsDataOffInsSizeValueFromIndex(DWORD dwOff)
{
	//如果传入的参数为0，则返回0
	if (dwOff == 0)
	{
		return 0;
	}
    PSTCodeItem pCI = (PSTCodeItem)(dwOff + getFileBeginAddr());
    return pCI->ins_size_;
}
//获取data_off_结构下的out_size_字段值
uint16_t CMyDexObj::getClassVirtualMethodsDataOffOutsSizeValueFromIndex(DWORD dwOff)
{
	//如果传入的参数为0，则返回0
	if (dwOff == 0)
	{
		return 0;
	}
    PSTCodeItem pCI = (PSTCodeItem)(dwOff + getFileBeginAddr());
    return pCI->outs_size_;
}
//获取data_off_结构下的tries_size_字段值
uint16_t CMyDexObj::getClassVirtualMethodsDataOffTriesSizeValueFromIndex(DWORD dwOff)
{
	//如果传入的参数为0，则返回0
	if (dwOff == 0)
	{
		return 0;
	}
    PSTCodeItem pCI = (PSTCodeItem)(dwOff + getFileBeginAddr());
    return pCI->tries_size_;
}
//获取data_off_结构下的debug_info_off_字段值
uint32_t CMyDexObj::getClassVirtualMethodsDataOffDebugInfoOffValueFromIndex(DWORD dwOff)
{
	//如果传入的参数为0，则返回0
	if (dwOff == 0)
	{
		return 0;
	}
    PSTCodeItem pCI = (PSTCodeItem)(dwOff + getFileBeginAddr());
    return pCI->debug_info_off_;
}
//获取data_off_结构下的insns数据大小，实际是WORD的个数
uint32_t CMyDexObj::getClassVirtualMethodsDataOffInsnsSizeInCodeUnitsValueFromIndex(DWORD dwOff)
{
	//如果传入的参数为0，则返回0
	if (dwOff == 0)
	{
		return 0;
	}
    PSTCodeItem pCI = (PSTCodeItem)(dwOff + getFileBeginAddr());
    return pCI->insns_size_in_code_units_;
}
//获取data_off_结构下的insns数据起始地址
WORD* CMyDexObj::getClassVirtualMethodsDataOffInsnsFileOffsetFromIndex(DWORD dwOff)
{
	//如果传入的参数为0，则返回0
	if (dwOff == 0)
	{
		return 0;
	}
    PSTCodeItem pCI = (PSTCodeItem)(dwOff + getFileBeginAddr());
	DWORD dwAdd = (DWORD)&pCI->insns_;
	DWORD dwFile = getFileBeginAddr();
    return (WORD*)(dwAdd - dwFile);
}
//获取ClassVirtualMethodsDataOffInsns下的机器码，返回值手动释放
//pSTCI 文件偏移指针
const char* CMyDexObj::getClassVirtualMethodsDataOffInsnsMachineCode(PSTCodeItem pSTCI)
{
    return getClassDirectMethodsDataOffInsnsMachineCode(pSTCI);
	
    //如果code字节码不为空
	
//     if (!pSTCI)
//     {
// 		char *result = new char[1];
//         return result;
//     }
// 	uint32_t dwSize = pSTCI->insns_size_in_code_units_;
// 	//" %02X %02X"
//     char *result = new char[dwSize * 6 + 1];
// 	result[0] = '\0';
//     char temp[MAXBYTE];
// 	
//     if(dwSize != 0)
//     {
//         for (uint32_t i = 0; i < dwSize;
//         i++)
//         {
//             //2个字节读出
//             uint16_t code = pSTCI->insns_[i];
//             
//             sprintf(temp, " %02X %02X", (BYTE)(code & 0xff),
//                 (BYTE)((code >> 8) & 0xff));
//             strcat(result, temp);
//         }
// 	}
//     return result;
}