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
/* �������ܣ�����LEB128ռ�ô�С
 * ��������: LEB128ָ��
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint getLeb128Size(BYTE *pByte)
{
    uint nLen = 1;
    //һ��ѭ������LEB128���5���ֽ�Ϊ����
    for(uint i = 0; i < LEB128MAXBYTESIZE; i++, pByte++)
    {
        //��ȡBYTEȡ����λ�ж��Ƿ�Ϊ1
        BYTE by = *pByte;
        //�����ʱ�ķ���λΪ0��LEB��չ����
        if ((by & 0x80) == 0)
        {
            return nLen + i;
        }
    }
    return 0;
}

///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡLEB128�洢��ʵ�ʱ�ʾ����
 * ��������: LEB128ָ��
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint readLeb128(BYTE *pByte)
{
    uint nRet = 0;
    uint nCur = 0;
    //һ��ѭ������LEB128���5���ֽ�Ϊ����
    for(uint i = 0; i < LEB128MAXBYTESIZE; i++, pByte++)
    {
        //��ȡBYTEȡ����λ�ж��Ƿ�Ϊ1
        BYTE by = *pByte;
        //������Σ������ۼ�
        nCur = by & 0x7f;
        nRet = nRet + (nCur << (7 * i));
        //�����ʱ�ķ���λΪ0��LEB��չ����
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
    m_nStringIdItemSize = 0;                //StringIdItem����
    m_pStringItem = NULL;                   //StringIdItemָ��
    
    m_nTypeIdItemSize = 0;                  //TypeIdItem����
    m_pTypeIdItem = NULL;                   //TypeIdItemָ��
    
    m_nProtoIdItemSize = 0;                 //ProtoIdItem����
    m_pProtoIdItem = NULL;                  //ProtoIdItemָ��

    m_nFieldIdItemSize = 0;                 //FieldIdItem����
    m_pFieldIdItem = NULL;                  //FieldIdItemָ��
    
    m_nMethodIdItemSize = 0;                //MethodIdItem����
    m_pMethodIdItem = NULL;                 //MethodIdItemָ��    
    
    m_nClassDefItemSize =0;                  //ClassDefItem����
    m_pClassDefItem = NULL;                   //ClassDefItemָ��
}
bool CMyDexObj::isDexFile()
{
    ASSERT(m_pHeader != NULL);

    return true;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ��ж�DEX�ļ��Ϸ��Բ������ʼ��������Ҫ�ֶ�
 * ��������: ��ȡ���ļ������׵�ַ
 * ��������ֵ��true������ʼ����false������
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::init(void *pContext)
{
    m_pNew = pContext;
    m_pHeader = (STHeader*)pContext;
    //����жϲ��ǺϷ�dex�ļ����˳�
    if(!isDexFile())
        return false;
    //ָ��map_list_type(��ʵ��MapInfo)�ṹ�ĵ�ַ=ͷ�ļ���ַ+map_off��ƫ��
    m_pMapInfo = (STMapInfo *)(m_pHeader->map_off_ + getFileBeginAddr());
    //ȡ��map_list��������
    m_nMapItemSize = m_pMapInfo->m_nSize;
    //ȡ��MapItem�ĵ�ַ����
    m_pMapItem = (STMapItem *)(m_pMapInfo->m_MapItem);

    //��ȡ�ַ�����Ϣ��Ҫ��������ȡ�ַ�����Ϣ
    initStringItemInfo();
    //��ȡtype_id_item��Ҫ����
    initTypeIdItemST();
    //��ȡproto_id_item��Ҫ����
    initProtoIdItemST();
    //��ȡfield_id_item��Ҫ����
    initFieldIdItemST();
    //��ȡmethod_id_item��Ҫ����
    initMethodIdItemST();
    //��ȡclassdef_item��Ҫ����
    initClassDefItemST();
    return true;
}
//��ȡMagic
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
DWORD CMyDexObj::getFileBeginAddr()       //��ȡ�ļ����ڴ���׵�ַ
{
    return (DWORD)m_pHeader;
}
//��ȡ�ļ�У����
uint32_t CMyDexObj::getChecksum()         
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->checksum_;
}
//��ȡǩ����Ϣ
BYTE* CMyDexObj::getSignature()           
{
    ASSERT(m_pHeader != NULL);
    return &m_pHeader->signature_[0];
}
//��ȡheader�ṹ��ָʾ���ļ���С
uint32_t CMyDexObj::getFileSize()         
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->file_size_;
}
//��ȡHEADER�ṹ��С
uint32_t CMyDexObj::getHeaderSize()       
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->header_size_;
}
//��ȡ��Сβ��־
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
/* �������ܣ�����Header�ṹ�е�StringIdsSize
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getStringIdsSize()    
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->string_ids_size_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ�����Header�ṹ�е�StringIds�ļ�ƫ��
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getStringIdsOff()     // file offset of StringIds array
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->string_ids_off_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ�
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getTypeIdsSize()      // number of TypeIds, we don't support more than 65535
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->type_ids_size_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ�
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getTypeIdsOff()       // file offset of TypeIds array
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->type_ids_off_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ�
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getProtoIdsSize()     // number of ProtoIds, we don't support more than 65535
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->proto_ids_size_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ�
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getProtoIdsOff()      // file offset of ProtoIds array
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->proto_ids_off_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ�
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getFieldIdsSize()     // number of FieldIds
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->field_ids_size_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ�
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getFieldIdsOff()      // file offset of FieldIds array
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->field_ids_off_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ�
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getMethodIdsSize()    // number of MethodIds
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->method_ids_size_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ�
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getMethodIdsOff()     // file offset of MethodIds array
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->method_ids_off_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ�
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassDefsSize()    // number of ClassDefs
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->class_defs_size_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ�
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassDefsOff()     // file offset of ClassDef array
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->class_defs_off_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ�
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getDataSize()         // unused
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->data_size_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ�
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getDataOff()          // unused
{
    ASSERT(m_pHeader != NULL);
    return m_pHeader->data_off_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ�
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const STMapInfo* CMyDexObj::getMapInfo()  //��map_list�ṹ��ʼ��ַ
{
    ASSERT(m_pMapInfo != NULL);
    return m_pMapInfo;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ�������ӦMapItem����ָ�����ͽṹ��ָ��
 * ��������: Ŀ¼Item����
 * ��������ֵ�����ڷ��ض�Ӧָ�룬���򷵻�-1
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
/* �������ܣ���ȡMapItem����
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint CMyDexObj::getMapItemSize()     
{
    return m_nMapItemSize;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ʼ��StringItem������� 
                m_pStringItem           //StringItem��ַ
                m_nStringIdItemSize     //String����
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::initStringItemInfo() 
{
    //����MapItem�Ƿ���ڶ�Ӧ���ͽṹ����
    STMapItem *pST = (STMapItem *)getMapItemWithType(kDexTypeStringIdItem);
    //�������
    if((DWORD)pST != EERROR)
    {
        //����ָ��StringItem��ָ��=MapItem�ṹָ���ƫ��+�ļ�ͷ��ַ
        m_pStringItem = (STStringIdItem*)((DWORD)pST->offset_ + getFileBeginAddr());
        //����StringItem����
        m_nStringIdItemSize = pST->size_;
        //ColletionStringIdItem();
    }
    return (DWORD)m_pStringItem != EERROR;
}

///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ʼ��TypeIdItem������� 
                m_pTypeIdItem           //TypeIdItem��ַ
                m_nTypeIdItemSize       //TypeIdItem����
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::initTypeIdItemST()      //��ʼ��type_id_item��Ҫ�ṹ
{
    //����MapItem�Ƿ���ڶ�Ӧ���ͽṹ����
    STMapItem *pST = (STMapItem *)getMapItemWithType(kDexTypeTypeIdItem);
    //�������
    if((DWORD)pST != EERROR)
    {
        //����ָ��TypeIdItem��ָ��=MapItem�ṹָ���ƫ��+�ļ�ͷ��ַ
        m_pTypeIdItem = (STTypeIdItem*)((DWORD)pST->offset_ + getFileBeginAddr());
        //����TypeItItem����
        m_nTypeIdItemSize = pST->size_;
        //ColletionTypeIdItem();
    }
    return (DWORD)m_pTypeIdItem != EERROR;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡMapItem�ṹ��StringItem����
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getStringItemSize()
{
    return m_nStringIdItemSize;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���string_id_listָ���±���ַ���
 * ��������: �±�
 * ��������ֵ��
*/
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getStringIdStringFromId(uint nIndex)
{
    ASSERT(nIndex < m_nStringIdItemSize && nIndex >= 0);
    //�ַ��������׵�ַ
    BYTE *pLeb128 = getStringIdItemAddrFromId(nIndex);
    //item�׵�ַΪleb128����������ָʾ���ITEM�е��ַ����ĳ���
    return (char *)((DWORD)pLeb128 + getLeb128Size(pLeb128));
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ָ���±��StringItem�׵�ַ
 * ��������: �±�
 * ��������ֵ��
*/
///////////////////////////////////////////////////////////////////////////
BYTE *CMyDexObj::getStringIdItemAddrFromId(uint nIndex)
{
    ASSERT(nIndex < m_nStringIdItemSize && nIndex >= 0);
    return (BYTE*)(getFileBeginAddr() + (DWORD)m_pStringItem[nIndex].m_nOffset);
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ָ���±��ַ����ĳ���
 * ��������: �±�
 * ��������ֵ��
*/
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getStringLenFromIndex(uint nIndex)
{
    ASSERT(nIndex < m_nStringIdItemSize && nIndex >= 0);
    BYTE *pByte = getStringIdItemAddrFromId(nIndex);

    return readLeb128(pByte);
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ָ���±��ַ����ĳ���
 * ��������: �±�
 * ��������ֵ��
*/
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getStringFillOffFromIndex(uint nIndex) //��ָ���±��ַ������ļ�ƫ��
{
    ASSERT(nIndex < m_nStringIdItemSize && nIndex >= 0);
    return m_pStringItem[nIndex].m_nOffset;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���type_id_listָ���±���ַ���
 * ��������: �±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getTypeIdStringFromId(uint nIndex)
{
    //����getStringFromId�ӿڣ�m_pTypeIdItem[nIndex].descriptor_idx_�ö�Ӧ�±�
    ASSERT(nIndex < m_nTypeIdItemSize && nIndex >= 0);
    return getStringIdStringFromId(m_pTypeIdItem[nIndex].descriptor_idx_);
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡtype_id_item����
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getTypeItemSize()
{
    return m_nTypeIdItemSize;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ��ռ��ַ�����
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::ColletionStringIdItem()
{
    for (DWORD i = 0; i < m_nStringIdItemSize; i++)
    {
        //http://androidxref.com/4.4.4_r1/xref/cts/tools/dex-tools/src/dex/reader/DexBuffer.java
        //�ַ��������׵�ַ
        //BYTE *pLeb128 = (BYTE*)(getFileBeginAddr() + (DWORD)m_pStringItem[i].m_nOffset);
//         BYTE *pLeb128 = getStringIdItemAddrFromId(i);
//         printf("%d pStrLen[%X]-> %x ==>%s\r\n", i, 
//             readLeb128(pLeb128), //LEBʵ�����ݴ�С
//             m_pStringItem[i].m_nOffset, //�ļ�ƫ��
//             (DWORD)pLeb128 + getLeb128Size(pLeb128));

        printf("%d pStrLen[%X]-> %x ==>%s\r\n", i, 
            getStringLenFromIndex(i), //LEBʵ�����ݴ�С
            getStringFillOffFromIndex(i), //�ļ�ƫ��
            getStringIdStringFromId(i));
    }
    return true;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ��ռ�type_id_item�������ͱ���
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::ColletionTypeIdItem()
{
    //ѭ������
    for (DWORD i = 0; i < getStringItemSize(); i++)
    {
        //����getTypeIdStringFromId�ӿڣ��±�
        printf("%d ==>%s\r\n", i, getTypeIdStringFromId(i));        
    }
    return true;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ʼ��proto_id_item��Ҫ�ṹ
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::initProtoIdItemST()
{
    //����MapItem�Ƿ���ڶ�Ӧ���ͽṹ����
    STMapItem *pST = (STMapItem *)getMapItemWithType(kDexTypeProtoIdItem);
    //�������
    if((DWORD)pST != EERROR)
    {
        //����ָ��ProtoIdItem��ָ��=MapItem�ṹָ���ƫ��+�ļ�ͷ��ַ
        m_pProtoIdItem = (STProtoIdItem*)((DWORD)pST->offset_ + getFileBeginAddr());
        //����ProtoIdItem����
        m_nProtoIdItemSize = pST->size_;
        //ColletionProtoIdItem();
    }
    return (DWORD)m_pProtoIdItem != EERROR;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ��ռ�proto_id_item��
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::ColletionProtoIdItem()
{
    STProtoIdItem *pST = NULL;
    for (DWORD i = 0; i < m_nProtoIdItemSize; i++)
    {
        //��ȡ���±����͵ĵ�ַ
        pST = getProtoIdSTFromId(i);
        ASSERT(pST != NULL);
#ifdef DEBUGLOG
        //�����ؽṹ����
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
/* �������ܣ���ָ���±귽���ļ��򷵻�ֵ�������ַ���
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getShortyIdxStringFromIndex(uint nIndex)
{
    //���ShortyIdx�ֶ�ʵ����ָ��StringId�ַ��������±꣬���÷��ؼ���
    return getStringIdStringFromId(getShortyIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ָ���±귽���ķ��������ַ���
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getReturnTypeIdxStringFromIndex(uint nIndex)
{
    //���return_type_idx_�ֶ�ʵ����ָ��TypeId�ַ��������±꣬���÷��ؼ���
    return getTypeIdStringFromId(getReturnTypeIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ָ���±귽���Ĳ����б��ַ���
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getParametersStringFromIndex(uint nIndex)
{
    char temp[MAXBYTE];
    char *tempret = new char[MAXBYTE * 4];
    tempret[0] = '\0';
    //�ò����ֶ�ƫ��
    DWORD dwOff = getParametersOffFromIndex(nIndex);
    //û�в���ʱ��offΪ0 
    if (dwOff != 0)
    {
        PSTTypeList pTL = (STTypeList*)(dwOff + getFileBeginAddr());
        sprintf(temp, "parameters_off[%d]: ", pTL->size_);
        strcpy(tempret, temp);
		//ѭ���������в���
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

DWORD CMyDexObj::getShortyIdxValueFromIndex(uint nIndex) //��ָ���±귽����ShortyIdx�ֶ�ֵ
{
    //ȡ��proto�ṹ�±�����
    STProtoIdItem *pST = NULL;
    pST = getProtoIdSTFromId(nIndex);
    return pST->shorty_idx_;
}
DWORD CMyDexObj::getReturnTypeIdxValueFromIndex(uint nIndex) //��ָ���±귽����ReturnTypeIdx�ֶ�ֵ 
{
    //ȡ��proto�ṹ�±�����
    STProtoIdItem *pST = NULL;
    pST = getProtoIdSTFromId(nIndex);
    return pST->return_type_idx_;
}
DWORD CMyDexObj::getParametersValueFromIndex(uint nIndex) //��ָ���±귽����Parameter�ֶ�ֵ
{
    //ȡ��proto�ṹ�±�����
    STProtoIdItem *pST = NULL;
    pST = getProtoIdSTFromId(nIndex);
    return pST->parameters_off_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���proto_id_listָ���±�Ľṹ�׵�ַ
 * ��������: nIndexҪ��ȡ���±�
 * ��������ֵ�����±�Ľṹ��ָ��
 */
///////////////////////////////////////////////////////////////////////////
STProtoIdItem* CMyDexObj::getProtoIdSTFromId(uint nIndex)
{
    ASSERT(m_pProtoIdItem != NULL);
    ASSERT(m_nProtoIdItemSize > nIndex && nIndex >= 0);
    return &m_pProtoIdItem[nIndex];
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ���±귽���Ĳ����б��ֶ�ֵ
 * ��������: nIndexҪ��ȡ���±�
 * ��������ֵ�������б��ֶ�ֵ
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
/* �������ܣ���ȡָ���±귽����TypeList�ṹ��ַ��ʵ���ڴ��ַ��
 * ��������: nIndexҪ��ȡ���±�
 * ��������ֵ�����±�Ľṹ��ָ��
 */
///////////////////////////////////////////////////////////////////////////
STTypeList *CMyDexObj::getTypeList(uint nIndex)
{
    DWORD dwParametersOff = getParametersOffFromIndex(nIndex);
    //�����б���Ϊ�ղŶ�ȡ����
    if(dwParametersOff != 0)
    {
        //ѭ���������
        STTypeList *pTL = (STTypeList *)(dwParametersOff + getFileBeginAddr());
        return pTL;
    }
    return NULL;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���proto_id_list����ָ���±�ĺ���ԭ����Ϣ,����ֵ��Ҫ�ֶ��ͷ�
 * ��������: nIndexҪ��ȡ���±�
 * ��������ֵ�����±�Ľṹ��ָ��
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
        //����ֵ�������б���
        sprintf(Tempret, "%s (", getTypeIdStringFromId(pST->return_type_idx_));
        DWORD dwOff = getParametersOffFromIndex(nIndex);
        //�����б���Ϊ�ղ���Ҫ��� 
        if(dwOff)
        {
            //ѭ���������
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
/* �������ܣ���ʼ��field_id_item��Ҫ�ṹ
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::initFieldIdItemST()
{
    //����MapItem�Ƿ���ڶ�Ӧ���ͽṹ����
    STMapItem *pST = (STMapItem *)getMapItemWithType(kDexTypeFieldIdItem);
    //�������
    if((DWORD)pST != EERROR)
    {
        //����ָ��FieldIdItem��ָ��=MapItem�ṹָ���ƫ��+�ļ�ͷ��ַ
        m_pFieldIdItem = (STFieldIdItem*)((DWORD)pST->offset_ + getFileBeginAddr());
        //����ProtoIdItem����
        m_nFieldIdItemSize = pST->size_;
        //ColletionFieldIdItem();
    }
    return (DWORD)m_pFieldIdItem != EERROR;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ��ռ�field_id_item��
 * ��������: nIndexҪ��ȡ���±�
 * ��������ֵ�����±�Ľṹ��ָ��
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::ColletionFieldIdItem()
{
    STFieldIdItem *pST = NULL;
    for (DWORD i = 0; i < getFieldIdSizeFromSave(); i++)
    {
        //��ȡ���±����͵ĵ�ַ
        pST = getFieldIdSTFromId(i);
        ASSERT(pST != NULL);
#ifdef DEBUGLOG
        //�����ؽṹ����
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
/* �������ܣ���field_id_listָ���±�Ľṹ�׵�ַ
 * ��������: nIndexҪ��ȡ���±�
 * ��������ֵ�����±�Ľṹ��ָ��
 */
///////////////////////////////////////////////////////////////////////////
STFieldIdItem* CMyDexObj::getFieldIdSTFromId(uint nIndex)
{
    ASSERT(m_pFieldIdItem != NULL);
    ASSERT(getFieldIdSizeFromSave() > nIndex && nIndex >= 0);
    return &m_pFieldIdItem[nIndex];
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���MethodId�ṹ����class_idx_�ֶ�ֵ
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getClassIdxValueFromId(uint nIndex)
{
	PSTMethodIdItem pST = getMethodIdSTFromId(nIndex);
	return pST->class_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���MethodId�ṹ����proto_idx_�ֶ�ֵ
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getProtoIdxValueFromId(uint nIndex)
{
	PSTMethodIdItem pST = getMethodIdSTFromId(nIndex);
	return pST->proto_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���MethodId�ṹ����name_idx_�ֶ�ֵ
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getNameIdxValueFromId(uint nIndex)
{
	PSTMethodIdItem pST = getMethodIdSTFromId(nIndex);
	return pST->name_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡFieldIdSize����
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getFieldIdSizeFromSave()
{
    return m_nFieldIdItemSize;
}

///////////////////////////////////////////////////////////////////////////
/* �������ܣ���field_id_item����ָ���±��class_idx_�ֶ�ֵ
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getFieldClassIdxValueFromIndex(uint nIndex)
{
	STFieldIdItem *pST = getFieldIdSTFromId(nIndex);
	return pST->class_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���field_id_item����ָ���±��type_idx_�ֶ�ֵ
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getFieldTypeIdxValueFromIndex(uint nIndex)
{
	STFieldIdItem *pST = getFieldIdSTFromId(nIndex);
	return pST->type_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���field_id_item����ָ���±��name_idx_�ֶ�ֵ
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getFieldNameIdxValueFromIndex(uint nIndex)
{
	STFieldIdItem *pST = getFieldIdSTFromId(nIndex);
	return pST->name_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���field_id_item����ָ���±��type_idx_��ʾ���ַ���
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getFieldTypeIdxStringFromId(uint nIndex)
{
	//��ȡtype_idx_�ֶ�ֵ,����ֶμ�Ϊtype_ids_�ַ��������±�
	//m_pDexObj->getTypeIdStringFromId(m_pDexObj->getProto_Idx_FromId(i)), 
	return getTypeIdStringFromId(getFieldTypeIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���field_id_item����ָ���±��class_idx_��ʾ���ַ���
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getFieldClassIdxStringFromId(uint nIndex)
{
	//��ȡclass_idx_�ֶ�ֵ������ֶμ�Ϊtype_ids_�ַ��������±�
	//m_pDexObj->getTypeIdStringFromId(m_pDexObj->getClass_Idx_FromId(i)), 
	return getTypeIdStringFromId(getFieldClassIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���field_id_item����ָ���±��name_idx_��ʾ���ַ���
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getFieldNameIdxStringFromId(uint nIndex)
{
	//��ȡname_idx_�ֶ�ֵ,����ֶμ�Ϊtype_ids_�ַ��������±�
	//m_pDexObj->getStringIdStringFromId(m_pDexObj->getName_Idx_FromId(i))
	return getStringIdStringFromId(getFieldNameIdxValueFromIndex(nIndex));
}

///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ʼ��method_id_item��Ҫ�ṹ
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::initMethodIdItemST()
{
    //����MapItem�Ƿ���ڶ�Ӧ���ͽṹ����
    STMapItem *pST = (STMapItem *)getMapItemWithType(kDexTypeMethodIdItem);
    //�������
    if((DWORD)pST != EERROR)
    {
        //����ָ��MethodIdItem��ָ��=MapItem�ṹָ���ƫ��+�ļ�ͷ��ַ
        m_pMethodIdItem = (STMethodIdItem*)((DWORD)pST->offset_ + getFileBeginAddr());
        //����ProtoIdItem����
        m_nMethodIdItemSize = pST->size_;
        //ColletionMethodIdItem();
    }
    return (DWORD)m_pMethodIdItem != EERROR;
}
bool CMyDexObj::ColletionMethodIdItem()     //�ռ�method_id_item��
{
    STMethodIdItem *pST = NULL;
    for (DWORD i = 0; i < getMethodIdSizeFromSave(); i++)
    {
        //��ȡ���±����͵ĵ�ַ
        pST = getMethodIdSTFromId(i);
        ASSERT(pST != NULL);
#ifdef DEBUGLOG
        //�����ؽṹ����
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
STMethodIdItem* CMyDexObj::getMethodIdSTFromId(uint nIndex)   //��method_id_listָ���±�Ľṹ�׵�ַ
{
    ASSERT(m_pMethodIdItem != NULL);
    ASSERT(getMethodIdSizeFromSave() > nIndex && nIndex >= 0);
    return &m_pMethodIdItem[nIndex];
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡFieldIdSize����
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getMethodIdSizeFromSave()
{
    ASSERT(m_nMethodIdItemSize != 0);
    return m_nMethodIdItemSize;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ʾ�����ַ���
 * ��������: 
 * ��������ֵ��
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
/* �������ܣ���method_id_item����ָ���±귽�������ַ���
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getMethodClassIdxStringFromIndex(uint nIndex)
{
	return getTypeIdStringFromId(getMethodClassIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���method_id_item����ָ���±귽���ķ���ԭ���ַ���
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getMethodProtoIdxStringFromIndex(uint nIndex)
{
	return getProtoIdStringFromId(getMethodProtoIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���method_id_item����ָ���±귽���ķ������ַ���
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getMethodNameIdxStringFromIndex(uint nIndex)
{
	return getStringIdStringFromId(getMethodNameIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���method_id_item����ָ���±��class_idx_�ֶ�ֵ
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getMethodClassIdxValueFromIndex(uint nIndex)
{
    STMethodIdItem *pST = getMethodIdSTFromId(nIndex);
	return pST->class_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���method_id_item����ָ���±��proto_idx_�ֶ�ֵ
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getMethodProtoIdxValueFromIndex(uint nIndex)
{
    STMethodIdItem *pST = getMethodIdSTFromId(nIndex);
	return pST->proto_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���method_id_item����ָ���±��name_idx_�ֶ�ֵ
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getMethodNameIdxValueFromIndex(uint nIndex)
{
    STMethodIdItem *pST = getMethodIdSTFromId(nIndex);
	return pST->name_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ʼ��classdef_item��Ҫ�ṹ
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::initClassDefItemST()
{
    //����MapItem�Ƿ���ڶ�Ӧ���ͽṹ����
    STMapItem *pST = (STMapItem *)getMapItemWithType(kDexTypeClassDefItem);
    //�������
    if((DWORD)pST != EERROR)
    {
        //����ָ��MethodIdItem��ָ��=MapItem�ṹָ���ƫ��+�ļ�ͷ��ַ
        m_pClassDefItem = (STClassDefItem*)((DWORD)pST->offset_ + 
                            getFileBeginAddr());
        //����ProtoIdItem����
        m_nClassDefItemSize = pST->size_;
        //ColletionClassDefItem();
    }
    return (DWORD)m_pClassDefItem != EERROR;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ��ռ�ClassDef_item��
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::ColletionClassDefItem()
{
    STClassDefItem *pST = NULL;
    for (DWORD i = 0; i < getClassDefSizeFromSave(); i++)
    {
        //��ȡ���±����͵ĵ�ַ
        pST = getClassDefSTFromId(i);
        ASSERT(pST != NULL);
#ifdef DEBUGLOG
        //�����ؽṹ����
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
        
        //������ʱ�־
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
//             case kAccSuper: //���ظ�����
//                 printf(" %s", "ACC_SUPER");
//                 break;
            case kAccVolatile:
                printf(" %s", "ACC_VOLATILE");
                break;
//             case kAccBridge: //���ظ�����
//                 printf(" %s", "ACC_BRIDGE");
//                 break;
            case kAccTransient:
                printf(" %s", "ACC_TRANSIENT");
                break;
//             case kAccVarargs: //���ظ�����
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

        //���interfaces_off�����Ϣ
        TypeList *pTL = NULL;
        //��interfaces_off_��Ϊ0
        if (pST->interfaces_off_ != 0)
        {
            //ƫ��+�׵�ַ
            pTL = (TypeList*)((DWORD)pST->interfaces_off_ + getFileBeginAddr());
            uint nSize = pTL->size_;
            STTypeItem *pSTTI = NULL;
            //��ȡʵ��Item
            pSTTI = (STTypeItem*)(&pTL->list_);
            printf("\t interfaces Size:%d ", nSize);
            //�������
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
            //������������leb128���ݱ�ʾ
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
            //���nstatic_fields_size_��Ч
            if (nstatic_fields_size_)
            {
                printf("\t\t nstatic_fields_size_[%d]\r\n", nstatic_fields_size_);
                for (int i = 0; i < nstatic_fields_size_; i++)
                {
                    //����Ϣ���
                    //ָ��fieldids���±�
                    int field_idx_diff = readLeb128((BYTE*)pNew);
                    nCount = getLeb128Size((BYTE*)pNew);
                    pNew = (pSTClassDataItem)((DWORD)pNew + nCount);
                    
                    //���ʱ�־
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

            //���ninstance_fields_size_��Ч
            if (ninstance_fields_size_)
            {
                printf("\t\t ninstance_fields_size_[%d]\r\n", ninstance_fields_size_);
                for (int i = 0; i < ninstance_fields_size_; i++)
                {
                    //����Ϣ���
                    //ָ��fieldids���±�
                    int field_idx_diff = readLeb128((BYTE*)pNew);
                    nCount = getLeb128Size((BYTE*)pNew);
                    pNew = (pSTClassDataItem)((DWORD)pNew + nCount);
                    
                    //���ʱ�־
                    int naccess_flags = readLeb128((BYTE*)pNew);
                    nCount = getLeb128Size((BYTE*)pNew);
                    pNew = (pSTClassDataItem)((DWORD)pNew + nCount);
                    
                    printf("\t\t\t [%d]method_idx_diff:%X access_flags:%X \r\n", 
                        i,
                        field_idx_diff,
                        naccess_flags);
                }
            }

            //���ndirect_methods_size_��Ч
            if (ndirect_methods_size_)
            {
                printf("\t\t ndirect_methods_size_[%d]\r\n", ndirect_methods_size_);
                for (int i = 0; i < ndirect_methods_size_; i++)
                {
                    //�������
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
                    //��ʾaccess_flags

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
                            //             case kAccSuper: //���ظ�����
                            //                 printf(" %s", "ACC_SUPER");
                            //                 break;
                        case kAccVolatile:
                            printf(" %s", "ACC_VOLATILE");
                            break;
                            //             case kAccBridge: //���ظ�����
                            //                 printf(" %s", "ACC_BRIDGE");
                            //                 break;
                        case kAccTransient:
                            printf(" %s", "ACC_TRANSIENT");
                            break;
                            //             case kAccVarargs: //���ظ�����
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
                        //���code�ֽ��벻Ϊ��
                        if(pSTCI->insns_size_in_code_units_ != 0)
                        {
                            printf("\t\t\t\t\t");
                            for (uint32_t i = 0; i < pSTCI->insns_size_in_code_units_;
                            i++)
                            {
                                //2���ֽڶ���
                                uint16_t code = pSTCI->insns_[i];
                                
                                printf(" %02X %02X", (BYTE)(code & 0xff),
                                    (BYTE)((code >> 8) & 0xff));
                            }
                            printf("\r\n");
                        }
                    } //if(ncode_off != 0)
                }
            }

            //���nvirtual_methods_size_��Ч
            if (nvirtual_methods_size_)
            {
                printf("\t\t nnvirtual_methods_size_[%d]\r\n", nvirtual_methods_size_);
                for (int i = 0; i < nvirtual_methods_size_; i++)
                {
                    //�������
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
                    //��ʾaccess_flags

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
                            //             case kAccSuper: //���ظ�����
                            //                 printf(" %s", "ACC_SUPER");
                            //                 break;
                        case kAccVolatile:
                            printf(" %s", "ACC_VOLATILE");
                            break;
                            //             case kAccBridge: //���ظ�����
                            //                 printf(" %s", "ACC_BRIDGE");
                            //                 break;
                        case kAccTransient:
                            printf(" %s", "ACC_TRANSIENT");
                            break;
                            //             case kAccVarargs: //���ظ�����
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
                        //���code�ֽ��벻Ϊ��
                        if(pSTCI->insns_size_in_code_units_ != 0)
                        {
                            printf("\t\t\t\t\t");
                            for (uint32_t i = 0; i < pSTCI->insns_size_in_code_units_;
                                 i++)
                            {
                                     //2���ֽڶ���
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
/* �������ܣ���ClassDef_listָ���±�Ľṹ�׵�ַ
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
STClassDefItem* CMyDexObj::getClassDefSTFromId(uint nIndex)
{
    ASSERT(m_pClassDefItem != NULL);
    ASSERT(getClassDefSizeFromSave() > nIndex && nIndex >= 0);
    return &m_pClassDefItem[nIndex];
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡClassDefSize����
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getClassDefSizeFromSave()
{
    ASSERT(m_nClassDefItemSize != 0);
    return m_nClassDefItemSize;
}

///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡclass_def_item�±�ṹ�е�class_idx_�ֶ�ֵ	
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getClassClassIdxValueFromIndex(uint nIndex)
{
	PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
	return pCD->class_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡclass_def_item�±�ṹ�е�pad1_�ֶ�ֵ	
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getClassPad1ValueFromIndex(uint nIndex)
{
	PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
	return pCD->pad1_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡclass_def_item�±�ṹ�е�access_flags_�ֶ�ֵ
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassAccessFlagsValueFromIndex(uint nIndex)
{
	PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
	return pCD->access_flags_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡclass_def_item�±�ṹ�е�superclass_idx_�ֶ�ֵ
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getClassSuperclassIdxValueFromIndex(uint nIndex)
{
	PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
	return pCD->superclass_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡclass_def_item�±�ṹ�е�pad2_�ֶ�ֵ	
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getClassPad2ValueFromIndex(uint nIndex)
{
	PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
	return pCD->pad2_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡclass_def_item�±�ṹ�е�interfaces_off�ֶ�ֵ
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassInterfaceOffValueFromIndex(uint nIndex)
{
	PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
	return pCD->interfaces_off_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡclass_def_item�±�ṹ�е�source_file_idx_�ֶ�ֵ
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassSourceFileIdxValueFromIndex(uint nIndex)
{
	PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
	return pCD->source_file_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡclass_def_item�±�ṹ�е�annotations_off_�ֶ�ֵ
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassAnnotationsOffValueFromIndex(uint nIndex)
{
	PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
	return pCD->annotations_off_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡclass_def_item�±�ṹ�е�class_data_off_�ֶ�ֵ
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassClassDataOffValueFromIndex(uint nIndex)
{
	PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
	return pCD->class_data_off_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡclass_def_item�±�ṹ�е�static_values_off_�ֶ�ֵ
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassStaticValuesOffValueFromIndex(uint nIndex)
{
	PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
	return pCD->static_values_off_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ���±��ClassDef�ṹ�е�class_idx_���ַ���
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getClassClassIdxStringFromIndex(uint nIndex)
{
	return getTypeIdStringFromId(getClassClassIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ���±��ClassDef�ṹ�е�access_flags_��ʾ���ַ���,����ֵ��Ҫ�ֶ��������ͷ�
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getClassAccessFlagsStringFromIndex(uint nIndex)
{
	DWORD dwFlags = getClassAccessFlagsValueFromIndex(nIndex);
	char *result = new char[MAXBYTE * 4];
	result[0] = '\0';
	char temp[MAXBYTE];

	//��flagsΪ0�򷵻�0
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
			//             case kAccSuper: //���ظ�����
			//                 printf(" %s", "ACC_SUPER");
			//                 break;
        case kAccVolatile:
            sprintf(temp, " %s", "ACC_VOLATILE");
			strcat(result, temp);
            break;
			//             case kAccBridge: //���ظ�����
			//                 printf(" %s", "ACC_BRIDGE");
			//                 break;
        case kAccTransient:
            sprintf(temp, " %s", "ACC_TRANSIENT");
			strcat(result, temp);
            break;
//             case kAccVarargs: //���ظ�����
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
/* �������ܣ���ȡָ���±��ClassDef�ṹ�е�superclass_idx_���ַ���
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getClassSuperClassIdxStringFromIndex(uint nIndex)
{
	return getTypeIdStringFromId(getClassSuperclassIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ���±��ClassDef�ṹ�е�source_file_idx_���ַ���
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getClassSourceFileIdxStringFromIndex(uint nIndex)
{
	return getStringIdStringFromId(getClassSourceFileIdxValueFromIndex(nIndex));
}