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
    //�ļ��Ƿ���dex 035��ͷ
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
 * ��������ֵ�����ڷ��ض�Ӧָ�룬���򷵻�NULL
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
// 	PSTMapItem pSI = getMapItemWithType(kDexTypeStringIdItem);
// 	return pSI->size_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���string_id_listָ���±���ַ���
 * ��������: �±�
 * ��������ֵ��
*/
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getStringIdStringFromIndex(uint nIndex)
{
    ASSERT(nIndex < m_nStringIdItemSize && nIndex >= 0);
    //��stringids��������±��string_data_off�ֶ�ֵ����Ϊ�ļ�ƫ��
    BYTE *pLeb128 = getStringIdsStringDataOffSTFromIndex(nIndex);
    if (!pLeb128)
    {
        return "getStringIdsStringDataOffSTFromIndex ret NULL!";
    }
    //����Ҫ��ȡ���ݱ����ȼ����ļ��׵�ַ
    pLeb128 = (BYTE *)((DWORD)pLeb128 + getFileBeginAddr());
    //item�׵�ַΪleb128����������ָʾ���ITEM�е��ַ����ĳ���
    return (char *)((DWORD)pLeb128 + getLeb128Size(pLeb128));
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���string_id_listָ���±��string_data_off�ֶ�ֵ��
              ��Ϊָ���StringItem�ṹ���ļ�ƫ�Ƶ�ַ
 * ��������: nIndex Ŀ��string_id_list�����±�
 * ��������ֵ��
*/
///////////////////////////////////////////////////////////////////////////
uint CMyDexObj::getStringIdsStringDataOffValueFromIndex(uint nIndex)
{
    ASSERT(nIndex < m_nStringIdItemSize && nIndex >= 0);
    return m_pStringItem[nIndex].m_nOffset;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���string_id_listָ���±��string_data_offָ���StringItem�Ľṹ�ļ�ƫ��
 * ��������: nIndex Ŀ��string_id_list�����±�
 * ��������ֵ��
*/
///////////////////////////////////////////////////////////////////////////
BYTE *CMyDexObj::getStringIdsStringDataOffSTFromIndex(uint nIndex)
{
    return (BYTE*)getStringIdsStringDataOffValueFromIndex(nIndex);
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
    //��stringids��������±��string_data_off�ֶ�ֵ
    BYTE *pByte = getStringIdsStringDataOffSTFromIndex(nIndex);
    //����жϺ�������������ַ�����ʼ��ַ�������ļ��׵�ַ�������
    if (!pByte)
    {
        return 0;
    }
    //����ֵʵ���ǽṹ���ļ���ƫ�Ƶ�ַ�����Լ����׵�ַ
    pByte = (BYTE *)(DWORD(pByte) + getFileBeginAddr());
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
const char* CMyDexObj::getTypeIdStringFromIndex(uint nIndex)
{
    //����getStringFromId�ӿڣ�m_pTypeIdItem[nIndex].descriptor_idx_�ö�Ӧ�±�
    ASSERT(nIndex < m_nTypeIdItemSize && nIndex >= 0);
//     if (!(nIndex < m_nTypeIdItemSize && nIndex >= 0))
//     {
//         printf("m_nTypeIdItemSize:%d nIndex:%d", m_nTypeIdItemSize, nIndex);
//     }
    return getStringIdStringFromIndex(m_pTypeIdItem[nIndex].descriptor_idx_);
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
            getStringIdStringFromIndex(i));
    }
    return true;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ��ռ�type_id_item�����ͱ�
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
        printf("%d ==>%s\r\n", i, getTypeIdStringFromIndex(i));        
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
        pST = getProtoIdsSTFromIndex(i);
        ASSERT(pST != NULL);
#ifdef DEBUGLOG
        //�����ؽṹ����
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
/* �������ܣ���ProteIdsָ���±귽���ļ��򷵻�ֵ�������ַ���
 * ��������: nIndex Ҫ��ȡ��protoids�±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getProtoIdsShortyIdxStringFromIndex(uint nProtoIdsIndex)
{
    //���ShortyIdx�ֶ�ʵ����ָ��StringId�ַ�������±꣬���÷��ؼ���
    return getStringIdStringFromIndex(getProtoIdsShortyIdxValueFromIndex(nProtoIdsIndex));
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ProteIdsָ���±귽���ķ��������ַ���
 * ��������: nIndex protoids�±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getProtoIdsReturnTypeIdxStringFromIndex(uint nProtoIdsIndex)
{
    //���return_type_idx_�ֶ�ʵ����ָ��TypeId�ַ�������±꣬���÷��ؼ���
    return getTypeIdStringFromIndex(getProtoIdsReturnTypeIdxValueFromIndex(nProtoIdsIndex));
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ָ���±귽���Ĳ����б��ַ���������ֵ��Ҫ�ֶ��ͷ�delete[] 
 * ��������: nIndex proto_ids���±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getProtoIdsParametersStringFromIndex(uint nProtoIdsIndex)
{
    char temp[MAXBYTE];
    char *tempret = new char[MAXBYTE * 4];
    tempret[0] = '\0';
    //��parameters_off�ֶ�ֵ
    DWORD dwOff = getProtoIdsParametersOffValueFromIndex(nProtoIdsIndex);
    //û�в���ʱ��offΪ0 
    if (dwOff != 0)
    {
		//dwOff = (DWORD)getProtoIdsTypeItemListSTFileOffsetFromIndex(nProtoIdsIndex)
        PSTTypeItemList pTL = (PSTTypeItemList)(dwOff + getFileBeginAddr());
        sprintf(temp, "parameters_off[%d]: ", pTL->size_);
        strcpy(tempret, temp);
		//ѭ���������в���
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
/* �������ܣ���ָ��proto_ids�±��ShortyIdx�ֶ�ֵ
 * ��������: nIndex proto_ids���±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getProtoIdsShortyIdxValueFromIndex(uint nProtoIdsIndex)
{
    //ȡ��proto�ṹ�±�����
    STProtoIdItem *pST = NULL;
    pST = getProtoIdsSTFromIndex(nProtoIdsIndex);
	//�쳣���
	if (!pST)
	{
		return 0;
	}
    return pST->shorty_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ָ���±귽����ReturnTypeIdx�ֶ�ֵ 
 * ��������: nIndex proto_ids���±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getProtoIdsReturnTypeIdxValueFromIndex(uint nProtoIdsIndex)
{
    //ȡ��proto�ṹ�±�����
    STProtoIdItem *pST = NULL;
    pST = getProtoIdsSTFromIndex(nProtoIdsIndex);
	//�쳣���
	if (!pST)
	{
		return 0;
	}
    return pST->return_type_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ָ���±귽����Parameter�ֶ�ֵ
 * ��������: nIndex proto_ids���±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
// DWORD CMyDexObj::getProtoIdsParametersValueFromIndex(uint nProtoIdsIndex)
// {
//     //ȡ��proto�ṹ�±�����
//     STProtoIdItem *pST = NULL;
//     pST = getProtoIdsSTFromIndex(nProtoIdsIndex);
// 	//�쳣���
// 	if (!pST)
// 	{
// 		return 0;
// 	}
//     return pST->parameters_off_;
// }
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���proto_id_listָ���±��proto_id_item�ṹ�׵�ַ
 * ��������: nIndexҪ��ȡ���±�
 * ��������ֵ�����±�Ľṹ��ָ��
 */
///////////////////////////////////////////////////////////////////////////
STProtoIdItem* CMyDexObj::getProtoIdsSTFromIndex(uint nProtoIdsIndex)
{
    ASSERT(m_pProtoIdItem != NULL);
    ASSERT(m_nProtoIdItemSize > nProtoIdsIndex && nProtoIdsIndex >= 0);
    return &m_pProtoIdItem[nProtoIdsIndex];
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ���±귽���Ĳ����б��ֶ�ֵ
 * ��������: nIndexҪ��ȡ���±�
 * ��������ֵ�������б��ֶ�ֵ
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getProtoIdsParametersOffValueFromIndex(uint nIndex)
{
    STProtoIdItem* pST = getProtoIdsSTFromIndex(nIndex);
    if(pST != NULL)
    {
        return pST->parameters_off_;
    }
    return 0;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ���±�parameters_offָ���TypeItemList
                {uint size; type_item list[size]}�ṹ�ļ�ƫ�Ƶ�ַ��
                ����ز���offΪ0�򷵻�ֵΪ��
 * ��������: nIndexҪ��ȡ���±�
 * ��������ֵ�����±�Ľṹ��ָ��
 */
///////////////////////////////////////////////////////////////////////////
STTypeItemList *CMyDexObj::getProtoIdsTypeItemListSTFileOffsetFromIndex(uint nIndex)
{
    return (STTypeItemList *)getProtoIdsParametersOffValueFromIndex(nIndex);
//     DWORD dwParametersOff = getProtoIdsParametersOffValueFromIndex(nIndex);
//     //�����б�Ϊ�ղŶ�ȡ����
//     if(dwParametersOff != 0)
//     {
//         //ѭ���������
//         STTypeItemList *pTL = (STTypeItemList *)(dwParametersOff);
//         return pTL;
//     }
//     return NULL;
}
const char* translateStanderType(char *pParemter)
{
    const char *pReal = NULL;
    switch(pParemter[0])
    {
    case 'B':
        pReal = "byte";
        break;
    case 'Z':
        pReal = "boolean";
        break;
    case 'C':
        pReal = "char";
        break;
    case 'I':
        pReal = "int";
        break;
    case 'F':
        pReal = "float";
        break;
    case 'S':
        pReal = "short";
        break;
    case 'J':
        pReal = "long";
        break;
    case 'D':
        pReal = "double";
        break;
    case 'V':
        pReal = "void";
        break;
    }
    return pReal;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���proto_id_list����ָ���±�ĺ���ԭ����Ϣ,����ֵ��Ҫ�ֶ��ͷ�
 * ��������: nIndexҪ��ȡ���±�
 * ��������ֵ�����±�Ľṹ��ָ��
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
        //����ֵ�������б�
        char *pRetString = (char*)getTypeIdStringFromIndex(pST->return_type_idx_);
        char *pReal = (char *)translateStanderType(pRetString);
        sprintf(Tempret, "%s (", pReal ? pReal : pRetString);
        DWORD dwOff = getProtoIdsParametersOffValueFromIndex(nIndex);
        //�����б�Ϊ�ղ���Ҫ��� 
        if(dwOff)
        {
            //ѭ���������
            STTypeItemList *pTL = (STTypeItemList *)(dwOff + getFileBeginAddr());
            for (DWORD i = 0; i < pTL->size_; i++)
            {
                pRetString = (char*)getTypeIdStringFromIndex(pTL->list_[i].type_idx_);
                pReal = (char *)translateStanderType(pRetString);
                sprintf(temp, pReal ? " %s;" : " %s", pReal ? pReal : pRetString);
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
/* �������ܣ����proto_id_list����ָ���±�ĺ���ԭ����Ϣ,����ֵ��Ҫ�ֶ��ͷ�
 * ��������: nIndexҪ��ȡ��proto_ids�±�
 * ��������ֵ�����±�Ľṹ��ָ��
 */
///////////////////////////////////////////////////////////////////////////
// const char* CMyDexObj::getProtoIdsProtoStringFromIndex(uint nIndex)
// {
//     char temp[MAXBYTE];
//     char *Tempret = new char[MAXBYTE *4];
//     Tempret[0] = '\0';
//     STProtoIdItem* pST = getProtoIdsSTFromIndex(nIndex);
//     if(pST != NULL)
//     {
//         //����ֵ�������б�
//         sprintf(Tempret, "%s (", getTypeIdStringFromIndex(pST->return_type_idx_));
// 		//��ȡparameter_off�ֶ�ֵ
//         DWORD dwOff = getProtoIdsParametersOffValueFromIndex(nIndex);
//         //�����б�Ϊ�ղ���Ҫ��� 
//         if(dwOff)
//         {
//             //ѭ���������
//             STTypeItemList *pTL = (STTypeItemList *)(dwOff + getFileBeginAddr());
//             for (DWORD i = 0; i < pTL->size_; i++)
//             {
//                 sprintf(temp, " %s", getTypeIdStringFromIndex(pTL->list_[i].type_idx_));
//                 strcat(Tempret, temp);
//             }
//         }
//         else
//             strcat(Tempret ,"void");
//         strcat(Tempret, ")");
//     }
//     return Tempret;
// }
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
    //������ز�Ϊ��
    if(pST)
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
        pST = getFieldIdSTFromIndex(i);
        ASSERT(pST != NULL);
#ifdef DEBUGLOG
        //�����ؽṹ����
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
/* �������ܣ���field_id_listָ���±��field_id_item�ṹ�׵�ַ
 * ��������: nIndexҪ��ȡ��fieldsids�±�
 * ��������ֵ�����±�Ľṹ��ָ��
 */
///////////////////////////////////////////////////////////////////////////
STFieldIdItem* CMyDexObj::getFieldIdSTFromIndex(uint nIndex)
{
    ASSERT(m_pFieldIdItem != NULL);
    ASSERT(getFieldIdSizeFromSave() > nIndex && nIndex >= 0);
    return &m_pFieldIdItem[nIndex];
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���MethodId�ṹ����ָ���±��field_id_item�ṹ��class_idx_�ֶ�ֵ
 * ��������: nIndex method_ids�����±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getFieldIdsClassIdxValueFromIndex(uint nIndex)
{
	PSTFieldIdItem pST = getFieldIdSTFromIndex(nIndex);
    if (!pST)
    {
        //return 0;
        return U16ERROR;
    }
	return pST->class_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���field_ids�ṹ����ָ���±��field_id_item�ṹ��proto_idx_�ֶ�ֵ
 * ��������: nIndex field_ids�����±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getFieldIdsTypeIdxValueFromIndex(uint nIndex)
{
    PSTFieldIdItem pST = getFieldIdSTFromIndex(nIndex);
    if (!pST)
    {
        //return 0;
        return U16ERROR;
    }
	return pST->type_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���FieldId�ṹ����ָ���±��field_id_item�ṹ��name_idx_�ֶ�ֵ
 * ��������: nIndex field_ids�����±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getFieldIdsNameIdxValueFromIndex(uint nIndex)
{
    PSTFieldIdItem pST = getFieldIdSTFromIndex(nIndex);
    if (!pST)
    {
        //return 0;
        return U32ERROR;
    }
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
/* �������ܣ���field_id_item����ָ���±��type_idx_�ֶ�ֵ
 * ��������: 
 * ��������ֵ��
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
/* �������ܣ���field_id_item����ָ���±��name_idx_�ֶ�ֵ
 * ��������: 
 * ��������ֵ��
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
/* �������ܣ���field_id_item����ָ���±��type_idx_��ʾ���ַ���
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getFieldTypeIdxStringFromIndex(uint nIndex)
{
	//��ȡtype_idx_�ֶ�ֵ,����ֶμ�Ϊtype_ids_�ַ��������±�
    //m_pDexObj->getTypeIdStringFromId(m_pDexObj->getProto_Idx_FromId(i)), 
    uint16_t value = getFieldIdsTypeIdxValueFromIndex(nIndex);
    if (value == U16ERROR)
    {
        //�������񲻴��
        return "getFieldIdsTypeIdxValueFromIndex ret -1";
    }
	return getTypeIdStringFromIndex(value);
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���field_id_item����ָ���±��class_idx_��ʾ���ַ���
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getFieldClassIdxStringFromIndex(uint nIndex)
{
	//��ȡclass_idx_�ֶ�ֵ������ֶμ�Ϊtype_ids_�ַ��������±�
	//m_pDexObj->getTypeIdStringFromId(m_pDexObj->getClass_Idx_FromId(i)), 
    uint16_t value = getFieldIdsClassIdxValueFromIndex(nIndex);
    if (value == U16ERROR)
    {
        //�������񲻴��
        return "getFieldIdsClassIdxValueFromIndex ret -1";
    }
	return getTypeIdStringFromIndex(value);
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���field_id_item����ָ���±��name_idx_��ʾ���ַ���
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getFieldNameIdxStringFromIndex(uint nIndex)
{
	//��ȡname_idx_�ֶ�ֵ,����ֶμ�Ϊtype_ids_�ַ��������±�
    //m_pDexObj->getStringIdStringFromId(m_pDexObj->getName_Idx_FromId(i))
    uint16_t value = getFieldIdsNameIdxValueFromIndex(nIndex);
    if (value == U32ERROR)
    {
        //�������񲻴��
        return "getFieldIdsNameIdxValueFromIndex ret -1";
    }
	return getStringIdStringFromIndex(value);
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ʼ������method_id_item��Ҫ�ṹ
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
    for (DWORD i = 0; i < getMethodIdsSizeFromSave(); i++)
    {
        //��ȡ���±����͵ĵ�ַ
        pST = getMethodIdSTFromIndex(i);
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
            getTypeIdStringFromIndex(pST->class_idx_));
        getProtoIdsProtoStringFromIndex(pST->proto_idx_);
        printf(" name_idx: %s\r\n", getStringIdStringFromIndex(pST->name_idx_));
    }
    return true;
}
    /*
		��method_id_list����ָ���±�Ľṹ�׵�ַ
	*/
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���method_id_listָ���±�Ľṹ�׵�ַ
    { uint16_t class_idx_; 
      uint16_t proto_idx_;
      uint32_t name_idx_;}
 * ��������: nIndex Ŀ��method_idx�±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
STMethodIdItem* CMyDexObj::getMethodIdSTFromIndex(uint nIndex)
{
    ASSERT(m_pMethodIdItem != NULL);
    ASSERT(getMethodIdsSizeFromSave() > nIndex && nIndex >= 0);
    return &m_pMethodIdItem[nIndex];
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡFieldIdsSize����
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getMethodIdsSizeFromSave()
{
    ASSERT(m_nMethodIdItemSize != 0);
    return m_nMethodIdItemSize;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡmethod_idsָ���±��ۺ��ַ�����Ϣ,����ֵ��Ҫ�ֶ�delete[]
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getMethodIdsStringFromIndex(uint nIndex)
{
    char *result = new char[MAXBYTE * 4];
    result[0] = '\0';

    ASSERT(m_pMethodIdItem != NULL);
    ASSERT(getMethodIdsSizeFromSave() > nIndex && nIndex >= 0);
    STMethodIdItem *pSTMI = &m_pMethodIdItem[nIndex];
    if (!pSTMI)
    {
        return result;
    }
    char *pRetString = (char*)getMethodIdsRetStringFromIndex(pSTMI->proto_idx_);
    char *pParemterString = (char*)getMethodIdsParemeterStringFromIndex(pSTMI->proto_idx_);

    sprintf(result, "%s %s.%s(%s)", pRetString,
        getTypeIdStringFromIndex(pSTMI->class_idx_),
        getStringIdStringFromIndex(pSTMI->name_idx_),
        pParemterString);
    delete[] pRetString;
    delete[] pParemterString;
    return result;
}
//��ȡmethod_idsָ���±귵������,����ֵ��Ҫ�ֶ�delete[]
const char* CMyDexObj::getMethodIdsRetStringFromIndex(uint nIndex)
{
    //getProtoIdStringFromId������ʽ���������� (�����б�)��
    char* pProto = (char*)getProtoIdsProtoStringFromIndex(nIndex);
    //����ȡ��һ���ո�λ��
    char *pdest = strchr(pProto, ' ');
    //�ո�λ-��ʼλ=���������ַ�������
    int nLocation = pdest - pProto;
    //���������ַ������� + 1 = new ����ĳ���
    int nSize = nLocation + sizeof(char);
    char *pRet = new char[nSize];
    if (!pRet)
    {
        return "new error!";
    }
    //�ÿ�
    memset(pRet, 0, nSize);
    //�����ַ���
    strncpy(pRet, pProto, nLocation);
    delete[] pProto;
    return pRet;
}
//��ȡmethod_idsָ���±��������,����ֵ��Ҫ�ֶ�delete[]
const char* CMyDexObj::getMethodIdsParemeterStringFromIndex(uint nIndex)
{
    //getProtoIdStringFromId������ʽ���������� (�����б�)��
    char* pProto = (char*)getProtoIdsProtoStringFromIndex(nIndex);
    //��λ(����λ��
    char *pdest = strchr(pProto, '(');
    //����proto�ַ�������
    int nProtoStringSize = strlen(pProto);
    //�õ�(����ǰ�ĳ���
    int nLocation = pdest - pProto;
    //��ȥ���������ַ�����ʣ�µĳ���
    int nNeed = nProtoStringSize - nLocation;
    //new ��Ҫ�õ��ĳ��ȿռ�
    int nSize = nNeed + sizeof(char);
    char *pRet = new char[nSize];
    if (!pRet)
    {
        return "new error!";
    }
    //�ÿ�
    memset(pRet, 0, nSize);
    //���Ʋ����б�
    strncpy(pRet, &pProto[nLocation] + sizeof(char), nNeed - sizeof(char) * 2);
    delete[] pProto;
    return pRet;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ʾָ�������±���ַ�������ʽΪ������.��������
 * ��������: nIndex ָ�������±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
void CMyDexObj::showMethodStringAt(uint nIndex)
{
    ASSERT(m_pMethodIdItem != NULL);
    ASSERT(getMethodIdsSizeFromSave() > nIndex && nIndex >= 0);
    STMethodIdItem *pSTMI = &m_pMethodIdItem[nIndex];
    getProtoIdsProtoStringFromIndex(pSTMI->proto_idx_);
    printf(" %s.%s\r\n",
        getTypeIdStringFromIndex(pSTMI->class_idx_), 
        getStringIdStringFromIndex(pSTMI->name_idx_));
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���method_id_item����ָ���±귽�������ַ���
 * ��������: nIndex ָ��method_id_item�����±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getMethodClassIdxStringFromIndex(uint nIndex)
{
    //��method_id_item����ָ���±��class_idx_�ֶ�ֵ����ʵ��Ϊ�ַ�����type_ids���±�
	return getTypeIdStringFromIndex(getMethodClassIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���method_id_item����ָ���±귽���ķ���ԭ���ַ���
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getMethodProtoIdxStringFromIndex(uint nIndex)
{
    //��method_id_item����ָ���±��class_idx_�ֶ�ֵ����ʵ��Ϊ�ַ�����proto_ids���±�
	return getProtoIdsProtoStringFromIndex(getMethodProtoIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���method_id_item����ָ���±귽���ķ������ַ���
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getMethodNameIdxStringFromIndex(uint nIndex)
{
    //��method_id_item����ָ���±��class_idx_�ֶ�ֵ����ʵ��Ϊ�ַ�����string_ids���±�
	return getStringIdStringFromIndex(getMethodNameIdxValueFromIndex(nIndex));
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���method_id_item����ָ���±��class_idx_�ֶ�ֵ����ʵ��Ϊ�ַ�����type_ids���±�
 * ��������: nIndex method_id_item�����±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getMethodClassIdxValueFromIndex(uint nIndex)
{
    STMethodIdItem *pST = getMethodIdSTFromIndex(nIndex);
    if (!pST)
    {
        return 0;
    }
	return pST->class_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���method_id_item����ָ���±��proto_idx_�ֶ�ֵ����ʵ��Ϊ�ַ�����proto_ids���±�
 * ��������: nIndex method_id_item�����±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getMethodProtoIdxValueFromIndex(uint nIndex)
{
    STMethodIdItem *pST = getMethodIdSTFromIndex(nIndex);
    if (!pST)
    {
        return 0;
    }
	return pST->proto_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���method_id_item����ָ���±��name_idx_�ֶ�ֵ����ʵ��Ϊ�ַ�����string_ids���±�
 * ��������: nIndex method_id_item�����±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getMethodNameIdxValueFromIndex(uint nIndex)
{
    STMethodIdItem *pST = getMethodIdSTFromIndex(nIndex);
    if (!pST)
    {
        return 0;
    }
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
                getTypeIdStringFromIndex(pST->class_idx_));
        
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
               getTypeIdStringFromIndex(pST->superclass_idx_),
               pST->interfaces_off_, 
               getStringIdStringFromIndex(pST->source_file_idx_),
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
            //������������leb128���ݱ�ʾ
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
                    pNew = (PSTClassDataItem)((DWORD)pNew + nCount);
                    
                    //���ʱ�־
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
                    pNew = (PSTClassDataItem)((DWORD)pNew + nCount);
                    
                    //���ʱ�־
                    int naccess_flags = readLeb128((BYTE*)pNew);
                    nCount = getLeb128Size((BYTE*)pNew);
                    pNew = (PSTClassDataItem)((DWORD)pNew + nCount);
                    
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
/* �������ܣ�������Ϣ�б�(ClassDef_list)ָ���±�Ľṹָ��
 * ��������: nIndex �±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
PSTClassDefItem CMyDexObj::getClassDefSTFromId(uint nIndex)
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
 * ��������: nIndex Ŀ��class_def_item�����±�
 * ��������ֵ��ʵ���ֶ�ֵ����U16ERROR
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getClassClassIdxValueFromIndex(uint nIndex)
{
	PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
    if (!pCD)
    {
        return U16ERROR;
    }
	return pCD->class_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡclass_def_item�±�ṹ�е�pad1_�ֶ�ֵ	
 * ��������: nIndex Ŀ��class_def_item�����±�
 * ��������ֵ��ʵ���ֶ�ֵ����U16ERROR
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getClassPad1ValueFromIndex(uint nIndex)
{
    PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
    if (!pCD)
    {
        return U16ERROR;
    }
	return pCD->pad1_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡclass_def_item�±�ṹ�е�access_flags_�ֶ�ֵ
 * ��������: nIndex Ŀ��class_def_item�����±�
 * ��������ֵ��ʵ���ֶ�ֵ����U32ERROR
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassAccessFlagsValueFromIndex(uint nIndex)
{
    PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
    if (!pCD)
    {
        return U32ERROR;
    }
	return pCD->access_flags_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡclass_def_item�±�ṹ�е�superclass_idx_�ֶ�ֵ
 * ��������: nIndex Ŀ��class_def_item�����±�
 * ��������ֵ��ʵ���ֶ�ֵ����U16ERROR
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getClassSuperclassIdxValueFromIndex(uint nIndex)
{
    PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
    if (!pCD)
    {
        return U16ERROR;
    }
	return pCD->superclass_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡclass_def_item�±�ṹ�е�pad2_�ֶ�ֵ	
 * ��������: nIndex Ŀ��class_def_item�����±�
 * ��������ֵ��ʵ���ֶ�ֵ����U16ERROR
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getClassPad2ValueFromIndex(uint nIndex)
{
    PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
    if (!pCD)
    {
        return U16ERROR;
    }
	return pCD->pad2_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡclass_def_item�±�ṹ�е�interfaces_off�ֶ�ֵ
 * ��������: nIndex Ŀ��class_def_item�����±�
 * ��������ֵ��ʵ���ֶ�ֵ����U32ERROR
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassInterfaceOffValueFromIndex(uint nIndex)
{
    PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
    if (!pCD)
    {
        return U32ERROR;
    }
	return pCD->interfaces_off_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡclass_def_item�±�ṹ�е�source_file_idx_�ֶ�ֵ
 * ��������: nIndex Ŀ��class_def_item�����±�
 * ��������ֵ��ʵ���ֶ�ֵ����U32ERROR
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassSourceFileIdxValueFromIndex(uint nIndex)
{
    PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
    if (!pCD)
    {
        return U32ERROR;
    }
	return pCD->source_file_idx_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡclass_def_item�±�ṹ�е�annotations_off_�ֶ�ֵ
 * ��������: nIndex Ŀ��class_def_item�����±�
 * ��������ֵ��ʵ���ֶ�ֵ����U32ERROR
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassAnnotationsOffValueFromIndex(uint nIndex)
{
    PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
    if (!pCD)
    {
        return U32ERROR;
    }
	return pCD->annotations_off_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡclass_def_item�±�ṹ�е�class_data_off_�ֶ�ֵ
 * ��������: nIndex Ŀ��class_def_item�����±�
 * ��������ֵ��ʵ���ֶ�ֵ����U32ERROR
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassClassDataOffValueFromIndex(uint nIndex)
{
    PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
    if (!pCD)
    {
        return U32ERROR;
    }
	return pCD->class_data_off_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡclass_def_item�±�ṹ�е�static_values_off_�ֶ�ֵ
 * ��������: nIndex Ŀ��class_def_item�����±�
 * ��������ֵ��ʵ���ֶ�ֵ����U32ERROR
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassStaticValuesOffValueFromIndex(uint nIndex)
{
    PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
    if (!pCD)
    {
        return U32ERROR;
    }
	return pCD->static_values_off_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ���±��ClassDef�ṹ�е�class_idx_���ַ���
 * ��������: nIndex Ŀ��class_def_item�����±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getClassClassIdxStringFromIndex(uint nIndex)
{
    //ȡ��Ӧclass_def_item�����µ�ClassDef�ṹ��class_idx_�ֶ�ֵ
    uint16_t value = getClassClassIdxValueFromIndex(nIndex);
    //����±�ֵΪtype_ids_�����±꣬����Ϊ0������ֻ��ܴ��󷵻�U16ERROR
    if (value == U16ERROR) //value == 0 || 
    {
        return "getClassClassIdxValueFromIndex ret -1";
    }
	return getTypeIdStringFromIndex((uint32_t)value);
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ���±��ClassDef�ṹ�е�access_flags_��ʾ���ַ���,����ֵ��Ҫ�ֶ��������ͷ�
 * ��������: nIndex Ŀ��class_def_item�����±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getClassAccessFlagsStringFromIndex(uint nIndex)
{
	DWORD dwFlags = getClassAccessFlagsValueFromIndex(nIndex);
	char *result = new char[MAXBYTE * 4];
	result[0] = '\0';
	char temp[MAXBYTE];

	//��flagsΪ0������-1�򷵻�0
	if(dwFlags == 0 || dwFlags == U32ERROR)
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
/* �������ܣ����ط��ʱ�־�ַ���������ֵ��Ҫ�ֶ�delete []
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getClassAccessFlagsString(DWORD dwFlags)
{
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
    //��ȡclass_def�ṹsuperclass_idx�ֶ�ֵ����Ϊ����·���ַ�����type_ids������±�
    uint16_t value = getClassSuperclassIdxValueFromIndex(nIndex);
    //�������
    if (value == U16ERROR)
    {
        return "getClassSuperclassIdxValueFromIndex ret -1";
    }
	return getTypeIdStringFromIndex(value);
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ���±��ClassDef�ṹ�е�source_file_idx_���ַ���
 * ��������: 
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getClassSourceFileIdxStringFromIndex(uint nIndex)
{
    //��ȡclass_def�ṹsource_file_idx�ֶ�ֵ����ΪԴ�ļ��ַ�����string_ids������±�
    uint32_t value = getClassSourceFileIdxValueFromIndex(nIndex);
    if (value == U32ERROR)
    {
        return "getClassSourceFileIdxValueFromIndex ret -1";
    }
	return getStringIdStringFromIndex(value);
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ�������ӦClass�ṹ�е�class_annotations_off_�ж��Ƿ���Ҫ��������Ϣ
 * ��������: nIndex ��Ӧclass���±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::isClassNeedShowAnnotationsString(uint nIndex)
{
    //��ȡ��ӦClass�ṹ�е�class_annotations_off_�ֶ�ֵ��
    //����ֵ��Ϊ�ջ�-1��ʾ���������
    return getClassAnnotationsOffValueFromIndex(nIndex) != 0 && 
        getClassAnnotationsOffValueFromIndex(nIndex) != U32ERROR;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡ��ӦClass�ṹ�е�class_annotations_off_�ṹ�����ַ���,����ֵ��Ҫ�ֶ��ͷ�
 * ��������: nIndex ��Ӧclass���±�
 * ��������ֵ��
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
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item�ṹ�±��STAnnotationsDirectoryItem�ṹ�ļ�ƫ��ָ��
 * ��������: nIndex ��Ӧclass���±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
PSTAnnotationsDirectoryItem CMyDexObj::
    getClassAnnotationsDirectoryItemSTFileOffsetFromIndex(uint nIndex)
{
    //��ȡ��ӦAnnotationsOff�ֶ�ֵ
    DWORD dwOff = getClassAnnotationsOffValueFromIndex(nIndex);
	//�쳣ʱ�Ĵ���ָ���±�ṹ��dwOffΪ�ջ򷵻ش���
	if (!dwOff || dwOff == U32ERROR)
	{
		return NULL;
	}

    //����ֶ�ֵ��Ϊ�ṹ���ļ���ƫ�ƣ������ļ���ʼ��ַ��Ϊ����ṹ��ָ��
    PSTAnnotationsDirectoryItem pAnnotationsDirectoryItem = 
        (PSTAnnotationsDirectoryItem)(dwOff/* + getFileBeginAddr()*/);
    return pAnnotationsDirectoryItem;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡ��ӦClass�ṹ�е�class_annotations_off_�ṹ��class_annotations_off_�ֶ�ֵ
 * ��������: nIndex ��Ӧclass���±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassAnnotationsClassAnnotationsOffValueFromIndex(uint nIndex)
{
    //��ȡ��Ӧclass_def_item�µ�annotations_off�ֶ�ֵ����Ϊ�ýṹ���ļ���ƫ��
    PSTAnnotationsDirectoryItem pAnnotationsDirectoryItem = 
        getClassAnnotationsDirectoryItemSTFileOffsetFromIndex(nIndex);
	//���pAnnotationsDirectoryItem��Ч�򷵻�0
	if (!pAnnotationsDirectoryItem)
	{
		return 0;
	}
    //�����׵�ַ
    pAnnotationsDirectoryItem = (PSTAnnotationsDirectoryItem)
        ((DWORD)pAnnotationsDirectoryItem + getFileBeginAddr());
    return pAnnotationsDirectoryItem->class_annotations_off_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡ��ӦClass�ṹ�е�class_annotations_off_�ṹ��fields_size_�ֶ�ֵ
 * ��������: nIndex ��Ӧclass���±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassAnnotationsFieldsSizeValueFromIndex(uint nIndex)
{
    //��ȡ��Ӧclass_def_item�µ�annotations_off�ֶ�ֵ����Ϊ�ýṹ���ļ���ƫ��
    PSTAnnotationsDirectoryItem pAnnotationsDirectoryItem = 
        getClassAnnotationsDirectoryItemSTFileOffsetFromIndex(nIndex);
	//���pAnnotationsDirectoryItem��Ч�򷵻�0
	if (!pAnnotationsDirectoryItem)
	{
		return 0;
    }
    //�����׵�ַ
    pAnnotationsDirectoryItem = (PSTAnnotationsDirectoryItem)
        ((DWORD)pAnnotationsDirectoryItem + getFileBeginAddr());
    return pAnnotationsDirectoryItem->fields_size_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡ��ӦClass�ṹ�е�class_annotations_off_�ṹ��methods_size_�ֶ�ֵ
 * ��������: nIndex ��Ӧclass���±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassAnnotationsMethodsSizeValueFromIndex(uint nIndex)
{
    //��ȡ��Ӧclass_def_item�µ�annotations_off�ֶ�ֵ����Ϊ�ýṹ���ļ���ƫ��
    PSTAnnotationsDirectoryItem pAnnotationsDirectoryItem = 
        getClassAnnotationsDirectoryItemSTFileOffsetFromIndex(nIndex);
	//���pAnnotationsDirectoryItem��Ч�򷵻�0
	if (!pAnnotationsDirectoryItem)
	{
		return 0;
    }
    //�����׵�ַ
    pAnnotationsDirectoryItem = (PSTAnnotationsDirectoryItem)
        ((DWORD)pAnnotationsDirectoryItem + getFileBeginAddr());
    return pAnnotationsDirectoryItem->methods_size_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡ��ӦClass�ṹ�е�class_annotations_off_�ṹ��parameters_size_�ֶ�ֵ
 * ��������: nIndex ��Ӧclass���±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassAnnotationsParametersSizeValueFromIndex(uint nIndex)
{
    //��ȡ��Ӧclass_def_item�µ�annotations_off�ֶ�ֵ����Ϊ�ýṹ���ļ���ƫ��
    PSTAnnotationsDirectoryItem pAnnotationsDirectoryItem = 
        getClassAnnotationsDirectoryItemSTFileOffsetFromIndex(nIndex);
	//���pAnnotationsDirectoryItem��Ч�򷵻�0
	if (!pAnnotationsDirectoryItem)
	{
		return 0;
    }
    //�����׵�ַ
    pAnnotationsDirectoryItem = (PSTAnnotationsDirectoryItem)
        ((DWORD)pAnnotationsDirectoryItem + getFileBeginAddr());
    return pAnnotationsDirectoryItem->parameters_size_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ�������ӦClass�ṹ�е�interfaces_off_�ֶ�ֵ�ж��Ƿ���Ҫ��������Ϣ
 * ��������: nIndex ��Ӧclass���±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::isClassNeedShowInterfacesString(uint nIndex)
{
    //��ȡָ���±��class_def_item�ṹ
    PSTClassDefItem pCD = getClassDefSTFromId(nIndex);
    //��ָ�뷵�ط�
    if (!pCD)
    {
        return false;
    }
    return pCD->interfaces_off_ != 0;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡ��ӦClass�ṹ�е�class_interfaces_off_�ṹ����,����ֵ��Ҫ�ֶ��ͷ�
 * ��������: nIndex ��Ӧclass���±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getClassInterfacesStringFromIndex(uint nIndex)
{
    char *result = new char[MAXBYTE * 4];
    result[0] = '\0';
    char temp[MAXBYTE];
    //��ȡָ��Class�±��interfaces_off_�ṹ�µ�list_�ṹ����
    DWORD dwSize = getClassInterfaceListSizeFromIndex(nIndex);
    //��ȡlist_�ṹ�ļ�ƫ�Ƶ�ַ
    PSTTypeItemList pTL = getClassInterfaceListSTFileOffsetFromIndex(nIndex);
	/*  ��ʱ��pTL�ṹΪ
		// Raw type_list. 
		typedef struct TypeList {
			uint32_t size_;             //ָʾ���listʵ��Item����
			TypeItem list_[1];          //TypeItem����
		} STTypeList, *PSTTypeList;
	*/
	//���interfaces_off_�����������򲻽��б����ռ�
	if (!dwSize || !pTL)
	{
		return result;
	}
	//���������pTL��һ���ļ�ƫ�ƣ����Լ����׵�ַ
	pTL = (PSTTypeItemList)(DWORD(pTL) + getFileBeginAddr());
    //list_��ַǿתΪTypeItem��ȡ�����ݼ�Ϊ����type_ids���±�
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
/* �������ܣ���ȡָ��Class�±��interfaces_off_�ֶ�ָ���type_item_list�ṹ���ļ��е�ƫ��
 * ��������: nIndex class_idsĿ���±�
 * ��������ֵ���ṹ�ļ�ƫ�ƻ��
 */
///////////////////////////////////////////////////////////////////////////
PSTTypeItemList CMyDexObj::getClassInterfaceListSTFileOffsetFromIndex(uint nIndex)  
{
    //��ȡClassDef->interfaces_off_�ֶ�ֵ
    DWORD dwOff = getClassInterfaceOffValueFromIndex(nIndex);
	//���interfaces_off_�ֶ�ֵΪ-1�򷵻ؿ�ָ��
	if (dwOff == U32ERROR)
	{
		return NULL;
	}
    //ֱ�ӷ�������ֶ�ֵ������ǽṹ���ļ���ƫ��
    PSTTypeItemList pTL = (PSTTypeItemList)
        (dwOff);
    return pTL;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��Class�±��interfaces_off_�ṹ�µ�list_�ṹ����
 * ��������: nIndex class_idsĿ���±�
 * ��������ֵ��interfaces_off_�ṹ�µ�list_�ṹ����
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassInterfaceListSizeFromIndex(uint nIndex)
{
	//��ƫ��
    PSTTypeItemList pTL = getClassInterfaceListSTFileOffsetFromIndex(nIndex);
	//���û��interfaces_off_���ݻ᷵�ؿգ������
	if (!pTL)
	{
		return 0;
	}
	//���׵�ַ��ȡ����
	pTL = (PSTTypeItemList)((DWORD)pTL + getFileBeginAddr());
    return pTL->size_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ�����class_def_item->class_data_off_�ֶ�ֵ�ж��Ƿ���Ҫ���
 * ��������: nIndex class_idsĿ���±�
 * ��������ֵ��true false
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::isClassNeedShowClassDataString(uint nIndex)
{
	//��Ӧclass_data_off_�ֶ�ֵ��Ϊ0�Ҳ�Ϊ-1��������
    return getClassClassDataOffValueFromIndex(nIndex) != 0 &&
        getClassClassDataOffValueFromIndex(nIndex) != U32ERROR;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡ��ӦClass�ṹ�е�class_data_off_ָ���
                class_data_item�ṹ�ַ�������,����ֵ��Ҫ�ֶ��ͷ�
 * ��������: nIndex class_idsĿ���±�
 * ��������ֵ���ַ���
 */
///////////////////////////////////////////////////////////////////////////
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
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item�ṹ�е�class_data_off�ֶ�ֵ��
                ��ΪSTClassDataItem�ṹ�ļ�ƫ��
 * ��������: nIndex class_idsĿ���±�
 * ��������ֵ���ṹ���ļ���ƫ�ƻ��쳣��
 */
///////////////////////////////////////////////////////////////////////////
PSTClassDataItem CMyDexObj::getClassClassDataSTFileOffsetFromIndex(uint nIndex)
{
	DWORD dwOff = getClassClassDataOffValueFromIndex(nIndex);
	if(dwOff == 0 || dwOff == U32ERROR)
		return NULL;
	PSTClassDataItem pCD = (PSTClassDataItem)(dwOff);
	return pCD;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item->class_data_off_->static_fields_size�ֶ�ֵ��
                ����LEB128��������
 * ��������: nIndex class_idsĿ���±�
 * ��������ֵ��StaticFieldSizeValue
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassClassDataStaticFieldsSizeValueFromIndex(uint nIndex)
{
	//��ȡ��Ӧclass_def_item->class_data_off_ָ��Ľṹ�ļ�ƫ��ָ��
	PSTClassDataItem pCDI = getClassClassDataSTFileOffsetFromIndex(nIndex);
	//ע�����ﵱoffΪ0ʱ����Ϊ�գ���Ҫ���⴦��һ��
	if(!pCDI)
		return 0;
    //��ַ+�׵�ַ
    pCDI = (PSTClassDataItem)(DWORD(pCDI) + getFileBeginAddr());
	BYTE *pByte = (BYTE*)pCDI;
	//��һ��LEB128������static_fields_size�ֶ�
	uint32_t nStaticFieldSizeValue = readLeb128(pByte);
	uint nSize = getLeb128Size(pByte);
	return nStaticFieldSizeValue;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item->class_data_off_->instance_fields_size�ֶ�ֵ��
                ����LEB128��������
 * ��������: nIndex class_idsĿ���±�
 * ��������ֵ��nInstanceFieldSizeValue
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassClassDataInstanceFieldsSizeValueFromIndex(uint nIndex)
{
	//��ȡ��Ӧclass_def_item->class_data_off_ָ��Ľṹ�ļ�ƫ��ָ��
	PSTClassDataItem pCDI = getClassClassDataSTFileOffsetFromIndex(nIndex);
	//����Ϊ�ռ�û��������͵�����
	if (!pCDI)
	{
		return 0;
    }
    //��ַ+�׵�ַ
    pCDI = (PSTClassDataItem)(DWORD(pCDI) + getFileBeginAddr());
    BYTE *pByte = (BYTE*)pCDI;
	//��һ��LEB128������static_fields_size�ֶ�
	uint32_t nStaticFieldSizeValue = readLeb128(pByte);
	uint nSize = getLeb128Size(pByte);
	//�ڶ���LEB128������instance_fields_size�ֶ�
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	uint32_t nInstanceFieldSizeValue = readLeb128(pByte);
	nSize = getLeb128Size(pByte);
	return nInstanceFieldSizeValue;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item->class_data_off_->direct_methods_size�ֶ�ֵ
                ����LEB128��������
 * ��������: nIndex class_idsĿ���±�
 * ��������ֵ��nDirectMethodsSizeValue
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassClassDataDirectMethodsSizeValueFromIndex(uint nIndex)
{
    //��ȡ��Ӧclass_def_item->class_data_off_ָ��Ľṹ�ļ�ƫ��ָ��
	PSTClassDataItem pCDI = getClassClassDataSTFileOffsetFromIndex(nIndex);
	if (pCDI == NULL)
	{
		return 0;
    }
    //��ַ+�׵�ַ
    pCDI = (PSTClassDataItem)(DWORD(pCDI) + getFileBeginAddr());
    BYTE *pByte = (BYTE*)pCDI;
	//��һ��LEB128������direct_methods_size�ֶ�
	uint32_t nStaticFieldSizeValue = readLeb128(pByte);
	uint nSize = getLeb128Size(pByte);
	//�ڶ���LEB128������instance_fields_size�ֶ�
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	uint32_t nInstanceFieldSizeValue = readLeb128(pByte);
	nSize = getLeb128Size(pByte);
	//������LEB128������direct_methods_size�ֶ�
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	uint32_t nDirectMethodsSizeValue = readLeb128(pByte);
	nSize = getLeb128Size(pByte);
	return nDirectMethodsSizeValue;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item->class_data_off_->virtual_methods_size�ֶ�ֵ
                ����LEB128�������ݱ�ʾ����ຬ�е�virtual_method����
 * ��������: nIndex class_idsĿ���±�
 * ��������ֵ��virtual_method����
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassClassDataVirtualMethodsSizeValueFromIndex(uint nIndex)
{
    //��ȡ��Ӧclass_def_item->class_data_off_ָ��Ľṹ�ļ�ƫ��ָ��
	PSTClassDataItem pCDI = getClassClassDataSTFileOffsetFromIndex(nIndex);
	if (pCDI == NULL)
	{
		return 0;
    }
    //��ַ+�׵�ַ
    pCDI = (PSTClassDataItem)(DWORD(pCDI) + getFileBeginAddr());
    BYTE *pByte = (BYTE*)pCDI;
	//��һ��LEB128������static_fields_size�ֶ�
	uint32_t nStaticFieldSizeValue = readLeb128(pByte);
	uint nSize = getLeb128Size(pByte);
	//�ڶ���LEB128������instance_fields_size�ֶ�
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	uint32_t nInstanceFieldSizeValue = readLeb128(pByte);
	nSize = getLeb128Size(pByte);
	//������LEB128������direct_methods_size�ֶ�
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	uint32_t nDirectMethodsSizeValue = readLeb128(pByte);
	nSize = getLeb128Size(pByte);
	//���ĸ�LEB128������virtual_methods_size�ֶ�
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	uint32_t nVirtualMethodsSizeValue = readLeb128(pByte);
	nSize = getLeb128Size(pByte);
	return nVirtualMethodsSizeValue;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item->class_data_off_->static_fields_size�ֶ�ʵ��ռ�õ��ֽڳ���
 * ��������: nIndex class_idsĿ���±�
 * ��������ֵ��static_fields_size�ֶ�leb����ʵ��ռ�õ��ֽڳ���
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassClassDataStaticFieldsSizeLenFromIndex(uint nIndex)
{
    //��ȡ��Ӧclass_def_item->class_data_off_ָ��Ľṹ�ļ�ƫ��ָ��
    PSTClassDataItem pCDI = getClassClassDataSTFileOffsetFromIndex(nIndex);
    if (!pCDI)
    {
        return 0;
    }
    //��ַ+�׵�ַ
    pCDI = (PSTClassDataItem)(DWORD(pCDI) + getFileBeginAddr());
    BYTE *pByte = (BYTE*)pCDI;
    //��һ��LEB128������static_fields_size�ֶ�
	uint nSize = getLeb128Size(pByte);
	return nSize;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item->class_data_off_->instance_fields_size�ֶ�ʵ��ռ�õ��ֽڳ���
 * ��������: nIndex class_idsĿ���±�
 * ��������ֵ��instance_fields_size�ֶ�leb����ʵ��ռ�õ��ֽڳ���
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassClassDataInstanceFieldsSizeLenFromIndex(uint nIndex)
{
    //��ȡ��Ӧclass_def_item->class_data_off_ָ��Ľṹ�ļ�ƫ��ָ��
    PSTClassDataItem pCDI = getClassClassDataSTFileOffsetFromIndex(nIndex);
    if (!pCDI)
    {
        return 0;
    }
    //��ַ+�׵�ַ
    pCDI = (PSTClassDataItem)(DWORD(pCDI) + getFileBeginAddr());
    BYTE *pByte = (BYTE*)pCDI;
	//��һ��LEB128������static_fields_size�ֶ�
	uint nSize = getLeb128Size(pByte);
	//�ڶ���LEB128������instance_fields_size�ֶ�
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	nSize = getLeb128Size(pByte);
	return nSize;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item->class_data_off_->direct_methods_size�ֶ�ʵ��ռ�õ��ֽڳ���
 * ��������: nIndex class_idsĿ���±�
 * ��������ֵ��direct_methods_size�ֶ�ʵ��ռ�õ��ֽڳ���
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassClassDataDirectMethodsSizeLenFromIndex(uint nIndex)
{
    //��ȡ��Ӧclass_def_item->class_data_off_ָ��Ľṹ�ļ�ƫ��ָ��
    PSTClassDataItem pCDI = getClassClassDataSTFileOffsetFromIndex(nIndex);
    if (!pCDI)
    {
        return 0;
    }
    //��ַ+�׵�ַ
    pCDI = (PSTClassDataItem)(DWORD(pCDI) + getFileBeginAddr());
    BYTE *pByte = (BYTE*)pCDI;
	//��һ��LEB128������static_fields_size�ֶ�
	uint nSize = getLeb128Size(pByte);
	//�ڶ���LEB128������instance_fields_size�ֶ�
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	nSize = getLeb128Size(pByte);
	//������LEB128������direct_methods_size�ֶ�
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	nSize = getLeb128Size(pByte);
	return nSize;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item->class_data_off_->virtual_methods_size�ֶ�ʵ��ռ�õ��ֽڳ���
 * ��������: nIndex class_idsĿ���±�
 * ��������ֵ��virtual_methods_size�ֶ�ʵ��ռ�õ��ֽڳ���
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassClassDataVirtualMethodsSizeLenFromIndex(uint nIndex)
{
    //��ȡ��Ӧclass_def_item->class_data_off_ָ��Ľṹ�ļ�ƫ��ָ��
    PSTClassDataItem pCDI = getClassClassDataSTFileOffsetFromIndex(nIndex);
	if (!pCDI)
	{
		return 0;
	}
    //��ַ+�׵�ַ
    pCDI = (PSTClassDataItem)(DWORD(pCDI) + getFileBeginAddr());
    BYTE *pByte = (BYTE*)pCDI;
	//��һ��LEB128������static_fields_size�ֶ�
	uint nSize = getLeb128Size(pByte);
	//�ڶ���LEB128������instance_fields_size�ֶ�
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	nSize = getLeb128Size(pByte);
	//������LEB128������direct_methods_size�ֶ�
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	nSize = getLeb128Size(pByte);
	//���ĸ�LEB128������virtual_methods_size�ֶ�
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	nSize = getLeb128Size(pByte);
	return nSize;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡclass_def_item->class_data_off_���ֶ�����ָ������׵�ַ��������Ϊʵ�����ݵ�����
 * ��������: nIndex class_idsĿ���±�
 * ��������ֵ���ֶ�����ָ������׵�ַ���߿�
 */
///////////////////////////////////////////////////////////////////////////
BYTE *CMyDexObj::getClassClassDataAttributeAddrFromIndex(uint nIndex)
{
    //��ȡ��Ӧclass_def_item->class_data_off_ָ��Ľṹ�ļ�ƫ��ָ��
    PSTClassDataItem pCDI = getClassClassDataSTFileOffsetFromIndex(nIndex);
    if (!pCDI)
    {
        return 0;
    }
    //��ַ+�׵�ַ
    pCDI = (PSTClassDataItem)(DWORD(pCDI) + getFileBeginAddr());
    BYTE *pByte = (BYTE*)pCDI;
	//��һ��LEB128������static_fields_size�ֶ�
	uint nSize = getLeb128Size(pByte);
	//�ڶ���LEB128������instance_fields_size�ֶ�
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	nSize = getLeb128Size(pByte);
	//������LEB128������direct_methods_size�ֶ�
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	nSize = getLeb128Size(pByte);
	//���ĸ�LEB128������virtual_methods_size�ֶ�
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	nSize = getLeb128Size(pByte);
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	return pByte;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ�ָ��class_def_item->class_data_off_->static_fields_size�ֶ�ֵ�Ƿ�Ϊ0
 * ��������: nIndex class_idsĿ���±�
 * ��������ֵ������������true�����򷵻�false
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::isClassNeedShowStaticFieldsStringFromIndex(uint nIndex)
{
	uint32_t nSize = getClassClassDataStaticFieldsSizeValueFromIndex(nIndex);
	return nSize != 0;
}
///////////////////////////////////////////////////////////////////////////
//�������ܣ���ȡָ��class_def_item->class_data_off_->static_fields_size�ֶε��ַ���,����ֵ��Ҫ�ֶ��ͷ�
//          ���ص�������ʽ��"[%d]method_idx_diff:%X access_flags:%X"
//��������: nIndex class_idsĿ���±�
//��������ֵ���ַ���ָ�� 
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getClassStaticFieldsStringFromIndex(uint nIndex, uint nFieldIndex)
{
	char *result = new char[MAXBYTE * 4];
	result[0] = '\0';
	//��ȡclass_data_off_��ַ�����ļ���ʼ�õ�4��leb128 size�ĵ�ַ
	PSTClassDataItem pCDI = getClassClassDataSTFileOffsetFromIndex(nIndex);
    //û��������ֱ�ӷ���
    if (!pCDI)
    {
        return result;
    }
    //ƫ�Ƶ�ַ+�׵�ַ
    pCDI = (PSTClassDataItem)(DWORD(pCDI) + getFileBeginAddr());
	//����4��leb128���ݳ��ȼ�Ϊ�����׵�ַ
	BYTE *pByte = getNextSTAddr((BYTE*)pCDI, 4);
	//��ȡstatic_fields_size_�ֶ�ֵ���������
	uint nstatic_fields_size = getClassClassDataStaticFieldsSizeValueFromIndex(nIndex);
	//������һ�������ֶ�Ϊ0ʱ��������
	if (nstatic_fields_size == 0 || nFieldIndex < 0 || nFieldIndex > nstatic_fields_size)
	{
		return result;
	}
	//Ŀ���ֶ���������Ԥ��ʱ���б���
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
		//ÿһ��fieldsռ����leb128����
		pByte = getNextSTAddr(pByte);
	}
	return result;
}
///////////////////////////////////////////////////////////////////////////
//�������ܣ���ȡָ��class_def_item->class_data_off_->
//            static_fields->field_idx_diff�ֶ�ֵ,����һ��LEB128����
//��������: nIndex class_idsĿ���±�
//��������ֵ��field_idx_diff leb�ֶ�ʵ��ֵ
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getClassStaticFieldsFieldIdxDiffValueIndex(BYTE *pByte)
{
	//��һ��leb128����Ϊfield_idx_diff�ֶ�ֵ
	int nfield_idx_diff = readLeb128(pByte);
	int nSize = getLeb128Size(pByte);
	return nfield_idx_diff;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item->class_data_off_->
                static_fields->access_flags�ֶ�ֵ,����һ��LEB128����
 * ��������: nIndex class_idsĿ���±�
 * ��������ֵ��access_flags leb�ֶ�ʵ��ֵ
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getClassStaticFieldsAccessFlagsValueIndex(BYTE *pByte)
{
	//��һ��leb128����Ϊfield_idx_diff�ֶ�ֵ
	int nfield_idx_diff = readLeb128(pByte);
	int nSize = getLeb128Size(pByte);
	//�����ŵ�leb128����Ϊaccess_flags�ֶ�ֵ
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	int naccess_flags = readLeb128(pByte);
	nSize = getLeb128Size(pByte);
	return naccess_flags;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ����ʼָ����LEB128���ݵ�BYTE��ַ��Ĭ��2��LEB128����Ϊ��
 * ��������: pByte ��ʼleb128��ַ
                nLeb128Count Ҫ������leb128����
 * ��������ֵ��ԭָ��+����������leb���ݳ���
 */
///////////////////////////////////////////////////////////////////////////
BYTE* CMyDexObj::getNextSTAddr(BYTE *pByte, int nLeb128Count)
{
	int nSize = 0;
	//���λ�ȡleb128���ȣ�����ָ�뷵��
	for (int i = 0; i < nLeb128Count; i++)
	{
		nSize = getLeb128Size(pByte);
		pByte = (BYTE *)(DWORD(pByte) + nSize);
	}
	return pByte;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ�����ָ��class_def_item[nIndex]->class_data_off_->instance_fields_size�ֶ�ֵ�Ƿ�Ϊ0
                ���ж��Ƿ���instance_fileds������Ҫ���
 * ��������: nIndex class_def_item�����±�
 * ��������ֵ���ֶβ�Ϊ0����true
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::isClassNeedShowInstanceFieldsStringFromIndex(uint nIndex)
{
	uint32_t nSize = getClassClassDataInstanceFieldsSizeValueFromIndex(nIndex);
	return nSize != 0;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item->class_data_off_->instance_fields_size�ֶε��ַ���,����ֵ��Ҫ�ֶ��ͷ�
 * ��������: nIndex class_def_item�����±�
                nFieldIndex field�±�
 * ��������ֵ�������ַ���
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getClassInstanceFieldsStringFromIndex(uint nIndex, uint nFieldIndex)
{
	char *result = new char[MAXBYTE * 4];
	result[0] = '\0';
	//��ȡinstance_fields_size_�ֶ�ֵ���������
	uint nstatic_fields_size = getClassClassDataInstanceFieldsSizeValueFromIndex(nIndex);
	//������һ�������ֶ�Ϊ0ʱ��������
	if (nstatic_fields_size == 0 || nFieldIndex < 0 || nFieldIndex > nstatic_fields_size)
	{
		return result;
	}
	//��ȡinstance_fields_size��Ӧ�Ľṹ�׵�ַ
	BYTE *pByte = getClassInstanceFieldsSTAddrFromIndex(nIndex);
    //instance_fields_size�ֶ�Ϊ0��class_data_offΪ0����ɷ��ؿ�ָ��
    if (!pByte)
    {
        return result;
    }
	//Ŀ���ֶ���������Ԥ��ʱ���б���
	for (uint i = 0; i < nstatic_fields_size; i++)
	{
		if (i == nFieldIndex)
		{
			sprintf(result, "[%d]field_idx_diff:%X access_flags:%X", 
				i,
				getClassStaticFieldsFieldIdxDiffValueIndex(pByte),
				getClassStaticFieldsAccessFlagsValueIndex(pByte));
			break;
		}
		//ÿһ��fieldsռ����leb128����
		pByte = getNextSTAddr(pByte);
	}
	return result;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item->class_data_off_->instance_fields_size->field_idx_diff�ֶ�ֵ,����һ��LEB128����
 * ��������: pByte InstanceFields�ṹ{leb128 field_idx_diff; leb128 access_flags;}�׵�ַ
 * ��������ֵ��field_idx_diff�ֶ�ʵ��ֵ
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getClassInstanceFieldsFieldIdxDiffValueIndex(BYTE *pByte)
{
	//��һ��leb128����Ϊfield_idx_diff�ֶ�ֵ
	int nfield_idx_diff = readLeb128(pByte);
	int nSize = getLeb128Size(pByte);
	return nfield_idx_diff;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item->class_data_off_->instance_fields_size->access_flags�ֶ�ֵ,����һ��LEB128����
 * ��������: pByte InstanceFields�ṹ{leb128 field_idx_diff; leb128 access_flags;}�׵�ַ
 * ��������ֵ��access_flags�ֶ�ʵ��ֵ
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getClassInstanceFieldsAccessFlagsValueIndex(BYTE *pByte)
{
	//��һ��leb128����Ϊfield_idx_diff�ֶ�ֵ
	int nfield_idx_diff = readLeb128(pByte);
	int nSize = getLeb128Size(pByte);
	//�����ŵ�leb128����Ϊaccess_flags�ֶ�ֵ
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	int naccess_flags = readLeb128(pByte);
	nSize = getLeb128Size(pByte);
	return naccess_flags;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item->class_data_off_->instance_fieldsָ������ݵ�ַ,
                instance_fields_size�ֶ�Ϊ0��class_data_offΪ0����ɷ��ؿ�ָ�룡����
 * ��������: nIndex class_def_item�����±�
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
BYTE* CMyDexObj::getClassInstanceFieldsSTAddrFromIndex(uint nIndex)
{
	//���⴦��
	uint nSize = getClassClassDataInstanceFieldsSizeValueFromIndex(nIndex);
	if (nSize == 0)
	{
		return NULL;
	}
	//���������class_data_item��ƫ�Ƶ�ַ
    PSTClassDataItem pCDI = getClassClassDataSTFileOffsetFromIndex(nIndex);
    if (!pCDI)
    {
        return NULL;
    }
    //�ṹ���׵�ַ+�ļ��׵�ַ
    pCDI = (PSTClassDataItem)(DWORD(pCDI) + getFileBeginAddr());
	//����4��leb��ʾ�ĸ����ֶε�����
	BYTE *pByte = getNextSTAddr((BYTE*)pCDI, 4);
	//����ǰ���м���static_fields����
	nSize = getClassClassDataStaticFieldsSizeValueFromIndex(nIndex);
	//ÿ��static_fields�ṹ��������LEB128���ݣ���������nSize*2��LEB���ݾͶ���
	pByte = getNextSTAddr(pByte, nSize * 2);
	return pByte;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ�ָ��class_def_item->class_data_off_->direct_methods_size�ֶ�ֵ�Ƿ�Ϊ0
 * ��������: nIndex class_def_item�����±�
 * ��������ֵ�������ݷ���true����false
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::isClassNeedShowDirectMethodsStringFromIndex(uint nIndex)
{
	uint32_t nSize = getClassClassDataDirectMethodsSizeValueFromIndex(nIndex);
	return nSize != 0;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item->class_data_off_->direct_methods_size�ֶε��ַ���,����ֵ��Ҫ�ֶ��ͷ�
 * ��������: nIndex class_def_item�����±�
                nFieldIndex class_def_item�ṹ�µ�field�����±�
 * ��������ֵ�������ݷ���true����false
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getClassDirectMethodsStringFromIndex(uint nIndex, uint nFieldIndex)
{
	char *result = new char[MAXBYTE * 4];
	result[0] = '\0';
	//��ȡdirect_method_size_�ֶ�ֵ���������
	uint ndirect_method_size = getClassClassDataDirectMethodsSizeValueFromIndex(nIndex);
	//������һ�������ֶ�Ϊ0ʱ��������
	if (ndirect_method_size == 0 || nFieldIndex < 0 || nFieldIndex > ndirect_method_size)
	{
		return result;
	}
	//��ȡdirect_methods_size��Ӧ�Ľṹ�׵�ַ
    BYTE *pByte = getClassDirectMethodsSTAddrFromIndex(nIndex);
    //direct_methods_size�ֶ�Ϊ0��class_data_offΪ0����ɷ��ؿ�ָ��
    if (!pByte)
    {
        return result;
    }
	//Ŀ���ֶ���������Ԥ��ʱ���б���
	for (uint i = 0; i < ndirect_method_size; i++)
	{
		if (i == nFieldIndex)
		{
// 			sprintf(result, "[%d]method_idx_diff:%X access_flags:%X code_off:%X", 
// 				i,
// 				getClassDirectMethodsMethodIdxDiffValueIndex(pByte),
// 				getClassDirectMethodsAccessFlagsValueIndex(pByte),
// 				getClassDirectMethodsCodeOffValueIndex(pByte));
// 			break;
            
            int nFieldIdxDiffValue = 0;
            int nBase = getClassDirectMethodsBaseMethodIdxFromIndex(nIndex);
            int nSub = getClassDirectMethodsMethodIdxSubFromIndex(nIndex, nFieldIndex);
            nFieldIdxDiffValue = nFieldIndex != 0 ? 
                nBase
                + nSub : nBase;
            
            sprintf(result, "[%d]method_idx_diff:%s access_flags:%X code_off:%X", 
                i,
                getMethodIdsStringFromIndex(nFieldIdxDiffValue),
                getClassDirectMethodsAccessFlagsValueIndex(pByte),
                getClassDirectMethodsCodeOffValueIndex(pByte));
			break;
		}
		//ÿһ��fieldsռ3��leb128����
		pByte = getNextSTAddr(pByte, 3);
	}
	return result;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item->class_data_off_->direct_methods_size->method_idx_diff�ֶ�ֵ,����һ��LEB128����
 * ��������: pByte directItem�ṹ{leb128 method_idx_diff; leb128 access_flags; leb128 code_off;}�׵�ַ
 * ��������ֵ��method_idx_diff�ֶ�ʵ��ֵ
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getClassDirectMethodsMethodIdxDiffValueIndex(BYTE *pByte)
{
	//��һ��leb128����Ϊmethod_idx_diff�ֶ�ֵ
	int nfield_idx_diff = readLeb128(pByte);
	int nSize = getLeb128Size(pByte);
	return nfield_idx_diff;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item->class_data_off_->direct_methods_size->access_flags�ֶ�ֵ,����һ��LEB128����
 * ��������: pByte directItem�ṹ{leb128 method_idx_diff; leb128 access_flags; leb128 code_off;}�׵�ַ
 * ��������ֵ��access_flags�ֶ�ʵ��ֵ
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getClassDirectMethodsAccessFlagsValueIndex(BYTE *pByte)
{
	//��һ��leb128����Ϊmethod_idx_diff�ֶ�ֵ
	int nfield_idx_diff = readLeb128(pByte);
	int nSize = getLeb128Size(pByte);
	//�����ŵ�leb128����Ϊaccess_flags�ֶ�ֵ
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	int naccess_flags = readLeb128(pByte);
	nSize = getLeb128Size(pByte);
	return naccess_flags;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item->class_data_off_->direct_methods_size->code_off�ֶ�ֵ,����һ��LEB128����
 * ��������: pByte directItem�ṹ{leb128 method_idx_diff; leb128 access_flags; leb128 code_off;}�׵�ַ
 * ��������ֵ��code_off�ֶ�ʵ��ֵ
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getClassDirectMethodsCodeOffValueIndex(BYTE *pByte)
{
	//��һ��leb128����Ϊmethod_idx_diff�ֶ�ֵ
	int nfield_idx_diff = readLeb128(pByte);
	int nSize = getLeb128Size(pByte);
	//�����ŵ�leb128����Ϊaccess_flags�ֶ�ֵ
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	int naccess_flags = readLeb128(pByte);
	nSize = getLeb128Size(pByte);
	//�����ŵ�leb128����Ϊcode_off�ֶ�ֵ
	pByte = (BYTE *)(DWORD(pByte) + nSize);
	int ncode_off = readLeb128(pByte);
	nSize = getLeb128Size(pByte);
	return ncode_off;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item->class_data_off_->direct_methods_size->code_off�ֶ�ֵ,����һ��LEB128����
 * ��������: nIndex class_def_item�����±�
                nFieldIndex ����class_def_item��Ӧ�ṹ��field�±�
 * ��������ֵ��code_off�ֶ�ʵ��ֵ
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getClassDirectMethodsCodeOffValueIndex(uint nIndex, uint nFieldIndex)
{
    //��ȡdirect_method_size_�ֶ�ֵ���������
    uint ndirect_method_size = getClassClassDataDirectMethodsSizeValueFromIndex(nIndex);
    //������һ�������ֶ�Ϊ0ʱ��������
    if (ndirect_method_size == 0 || nFieldIndex < 0 || nFieldIndex > ndirect_method_size)
    {
        return 0;
    }
    //��ȡdirect_methods_size��Ӧ�Ľṹ�׵�ַ,����leb128���ݷֱ��ʾmethods_idx_diff,access_flags,code_off
    BYTE *pByte = getClassDirectMethodsSTAddrFromIndex(nIndex);
    //direct_methods_size�ֶ�Ϊ0��class_data_offΪ0����ɷ��ؿ�ָ��
    if (!pByte)
    {
        return 0;
    }
    //Ŀ���ֶ���������Ԥ��ʱ���б���
    for (uint i = 0; i < ndirect_method_size; i++)
    {
        if (i == nFieldIndex)
        {
            return getClassDirectMethodsCodeOffValueIndex(pByte);
        }
        //ÿһ��fieldsռ3��leb128����
        pByte = getNextSTAddr(pByte, 3);
    }
    return 0;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item->class_data_off_->direct_methods_size��Ӧ�����ݵ�ַ,û���򷵻ؿ�ָ�룡����
 * ��������: nIndex class_def_item�����±�
 * ��������ֵ����Ӧ�������׵�ַ
 */
///////////////////////////////////////////////////////////////////////////
BYTE* CMyDexObj::getClassDirectMethodsSTAddrFromIndex(uint nIndex)
{
	//���⴦��
	uint nSize = getClassClassDataDirectMethodsSizeValueFromIndex(nIndex);
	if (nSize == 0)
	{
		return NULL;
	}
	//���������Class�ĵ�ַ
    PSTClassDataItem pCDI = getClassClassDataSTFileOffsetFromIndex(nIndex);
    if (!pCDI)
    {
        return NULL;
    }
    //�ṹ���׵�ַ+�ļ��׵�ַ
    pCDI = (PSTClassDataItem)(DWORD(pCDI) + getFileBeginAddr());
	//����4��leb��ʾ�ĸ����ֶε�����
	BYTE *pByte = getNextSTAddr((BYTE*)pCDI, 4);
	//����ǰ���м���static_fields����
	nSize = getClassClassDataStaticFieldsSizeValueFromIndex(nIndex);
	//����ǰ���м���instance_fields����
	nSize += getClassClassDataInstanceFieldsSizeValueFromIndex(nIndex);
	//ÿ��static_fields�ṹ��������LEB128���ݣ���������nSize*2��LEB���ݾͶ���
	pByte = getNextSTAddr(pByte, nSize * 2);
	return pByte;
}
//��ȡָ����DirectMethodָ������ݽṹ��method_idx����
uint32_t CMyDexObj::getClassDirectMethodsBaseMethodIdxFromIndex(uint nIndex)
{
    //��ȡ����׵�ַ
    BYTE *pByte = getClassDirectMethodsSTAddrFromIndex(nIndex);
    if (!pByte)
    {
        return 0;
    }
    //�׵�ַ��Ϊleb128���͵�method_idx_diffֵ
    return readLeb128(pByte);
}
//��ȡָ����DirectMethodָ������ݽṹ��idx���ܶ�
uint32_t CMyDexObj::getClassDirectMethodsMethodIdxSubFromIndex(uint nIndex, uint nMethodIndex)
{
    //��ȡ����׵�ַ
    BYTE *pByte = getClassDirectMethodsSTAddrFromIndex(nIndex);
    if (!pByte)
    {
        return 0;
    }
    //����3��leb128����һ�ṹ
    pByte = getNextSTAddr(pByte, 3);
    int nSub = 0;
    //�ۼ�
    for (uint i = 1; i <= nMethodIndex; i++)
    {
        nSub += readLeb128(pByte);
        //�ƶ�����һ���ṹ��ַ
        pByte = getNextSTAddr(pByte, 3);
    }
    return nSub;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item->class_data_off_->direct_methods_size->data_off_�Ƿ���Ҫ���
 * ��������: nIndex class_def_item�����±�
 * ��������ֵ����Ӧdirect_methods_size->data_off_�ַ���Ϊ0�򷵻�true,���򷵻�false
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::isClassDirectMethodsNeedShowDataOffStringFromIndex(uint nIndex)
{
    //��ȡָ���±��µ�class_def_item->class_data_off_->direct_methods_size��Ӧ���׵�ַ
    BYTE *pByte = getClassDirectMethodsSTAddrFromIndex(nIndex); //getClassVirtualMethodsAddrFromIndex
    if(pByte == NULL)
        return false;
    
    //��Ӧ�ṹoff��Ϊ0��ʾ������Ч
    DWORD dwOff = getClassDirectMethodsCodeOffValueIndex(pByte);
    return dwOff != 0;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ�����±�ָ��DirectMethod���ֽ���
 * ��������: nClassIndex nDirectMethodIndex
 * ��������ֵ��
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getClassDirectMethodsDataOffStringFromIndex(uint nClassIndex, uint nDirectMethodIndex)
{
	DWORD dwOff = getClassDirectMethodsCodeOffValueIndex(nClassIndex, nDirectMethodIndex);
    if (!dwOff)
    {
        return "getClassDirectMethodsCodeOffValueIndex == 0";
    }
	return getClassDirectMethodsDataOffStringFromIndex(dwOff);
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item->class_data_off_->direct_methods_size->data_off_�ֽ���
                ����ֵ��Ҫ�ֶ��ͷ�delete[] 
 * ��������: 
 * ��������ֵ��
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
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡdwOffָ��code_item�ṹ��register_size_�ֶ�ֵ
 * ��������: dwOff code_item�ṹ���׵�ַ
 * ��������ֵ��register_size_�ֶ�ֵ
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getClassDirectMethodsDataOffRegisterSizeValueFromIndex(DWORD dwOff)
{
    return getClassVirtualMethodsDataOffRegisterSizeValueFromIndex(dwOff);
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡdwOffָ��code_item�ṹ��ins_size_�ֶ�ֵ
 * ��������: dwOff code_item�ṹ���׵�ַ
 * ��������ֵ��ins_size_�ֶ�ֵ
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getClassDirectMethodsDataOffInsSizeValueFromIndex(DWORD dwOff)
{
    return getClassVirtualMethodsDataOffInsSizeValueFromIndex(dwOff);
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡdwOffָ��code_item�ṹ��out_size_�ֶ�ֵ
 * ��������: dwOff code_item�ṹ���׵�ַ
 * ��������ֵ��out_size_�ֶ�ֵ
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getClassDirectMethodsDataOffOutsSizeValueFromIndex(DWORD dwOff)
{
    return getClassVirtualMethodsDataOffOutsSizeValueFromIndex(dwOff);
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡdwOffָ��code_item�ṹ��tries_size_�ֶ�ֵ
 * ��������: dwOff code_item�ṹ���׵�ַ
 * ��������ֵ��tries_size_�ֶ�ֵ
 */
///////////////////////////////////////////////////////////////////////////
uint16_t CMyDexObj::getClassDirectMethodsDataOffTriesSizeValueFromIndex(DWORD dwOff)
{
    return getClassVirtualMethodsDataOffTriesSizeValueFromIndex(dwOff);
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡdwOffָ��code_item�ṹ��debug_info_off_�ֶ�ֵ
 * ��������: dwOff code_item�ṹ���׵�ַ
 * ��������ֵ��debug_info_off_�ֶ�ֵ
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassDirectMethodsDataOffDebugInfoOffValueFromIndex(DWORD dwOff)
{
    return getClassVirtualMethodsDataOffDebugInfoOffValueFromIndex(dwOff);
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡdwOffָ��code_item�ṹ�µ�insns���ݴ�С��ʵ����WORD�ĸ���
 * ��������: dwOff code_item�ṹ���׵�ַ
 * ��������ֵ��insns�����ֶ�ֵ
 */
///////////////////////////////////////////////////////////////////////////
uint32_t CMyDexObj::getClassDirectMethodsDataOffInsnsSizeInCodeUnitsValueFromIndex(DWORD dwOff)
{
    return getClassVirtualMethodsDataOffInsnsSizeInCodeUnitsValueFromIndex(dwOff);
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡdwOffָ��code_item�ṹ�µ�insns����(������)��ʼ��ַ
 * ��������: dwOff code_item�ṹ���׵�ַ
 * ��������ֵ��insns����(������)��ʼ��ַ
 */
///////////////////////////////////////////////////////////////////////////
WORD* CMyDexObj::getClassDirectMethodsDataOffInsnsFileOffsetFromIndex(DWORD dwOff)
{
    return getClassVirtualMethodsDataOffInsnsFileOffsetFromIndex(dwOff);
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ����ָ��directmethod�Ļ����룬����ֵ�ֶ��ͷ�
 * ��������: nClassIndex ���±�
                nDirectMethodIndex �����±�
 * ��������ֵ���������ַ���
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getClassDirectMethodsDataOffInsnsMachineCode(uint nClassIndex, uint nDirectMethodIndex)
{
	//��ȡָ�����µ�ָ���±�DirectMethods��CodeOff�ֶ�ֵ�����ļ�ƫ�ƣ�
    //������ļ�ƫ����getClassDirectMethodsDataOffInsnsMachineCode����ȥ��ȡ
	DWORD dwOff = getClassDirectMethodsCodeOffValueIndex(nClassIndex, nDirectMethodIndex);
    //getClassDirectMethodsDataOffInsnsMachineCode�ڲ����жϿ�ָ��
	return getClassDirectMethodsDataOffInsnsMachineCode((PSTCodeItem)dwOff);
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ�����pSTCI�ṹ��ȡ���е�directmethod�����룬����ֵ�ֶ��ͷ�
 * ��������: pSTCI STCodeItem�ļ�ƫ��ָ��
 * ��������ֵ���������ַ���
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getClassDirectMethodsDataOffInsnsMachineCode(PSTCodeItem pSTCI)
{
    if (!pSTCI)
    {
		char *result = new char[1];
        return result;
    }
    //ƫ��+�׵�ַ
	pSTCI = (PSTCodeItem)((DWORD)pSTCI + getFileBeginAddr());
	uint32_t dwSize = pSTCI->insns_size_in_code_units_;
    if (!dwSize)
    {
        char *result = new char[1];
        return result;
    }
	//" %02X %02X"ÿһ��ѭ������6���ֽڣ�+һ���ֽڽ�β
    char *result = new char[dwSize * 6 + 1];
	result[0] = '\0';
    char temp[MAXBYTE];
	
    if(dwSize != 0)
    {
        for (uint32_t i = 0; i < dwSize;
        i++)
        {
            //2���ֽڶ���
            uint16_t code = pSTCI->insns_[i];
            
            sprintf(temp, " %02X %02X", (BYTE)(code & 0xff),
                (BYTE)((code >> 8) & 0xff));
            strcat(result, temp);
        }
	}
    return result;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ�ָ��class_def_item->class_data_off_->virtual_methods_size�ֶ�ֵ�Ƿ�Ϊ0
 * ��������: nIndex class_def_item�����±�
 * ��������ֵ��virtual_methods_size�ֶ�ֵΪ0����false,���򷵻�true
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::isClassNeedShowVirtualMethodsStringFromIndex(uint nIndex)
{
	uint32_t nSize = getClassClassDataVirtualMethodsSizeValueFromIndex(nIndex);
	return nSize != 0;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item->class_data_off_->
                virtual_methods_size�ֶζ�Ӧ�ṹ���ַ�����Ϣ,����ֵ��Ҫ�ֶ��ͷ�
 * ��������: nIndex class_def_item�����±�
                nFieldIndex field�±�
 * ��������ֵ��virtual_methods_size�ֶ�ֵΪ0����false,���򷵻�true
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getClassVirtualMethodsSTStringFromIndex(uint nIndex, uint nFieldIndex)
{
	char *result = new char[MAXBYTE * 4];
	result[0] = '\0';
	//��ȡdirect_method_size_�ֶ�ֵ���������
	uint nvirtual_method_size = getClassClassDataVirtualMethodsSizeValueFromIndex(nIndex);
	//������һ�������ֶ�Ϊ0ʱ��������
	if (nvirtual_method_size == 0 || nFieldIndex < 0 || nFieldIndex > nvirtual_method_size)
	{
		return result;
	}
	//��ȡvirtual_methods_size��Ӧ�Ľṹ�׵�ַ
	BYTE *pByte = getClassVirtualMethodsSTAddrFromIndex(nIndex);
    //�������
    if (!pByte)
    {
		return result;
    }
	//Ŀ���ֶ���������Ԥ��ʱ���б���
	for (uint i = 0; i < nvirtual_method_size; i++)
	{
		if (i == nFieldIndex)
        {
            DWORD dwFlags = getClassVirtualMethodsAccessFlagsValueIndex(pByte);
            uint32_t nFieldIdxDiffValue = getClassVirtualMethodsFieldIdxDiffValueIndex(pByte);
            // 			printf("[%d]method_idx_diff:%X access_flags:%X code_off:%X", 
            // 				i,
            // 				nFieldIdxDiffValue,
            // 				dwFlags,
            // 				getClassVirtualMethodsCodeOffValueIndex(pByte));
            
            const char* p = getClassAccessFlagsString(dwFlags);
            //������ǵ�ǰ��һ��method��nFieldIdxDiffValue������ϻ�����֮ǰ�����󵽵�ǰ��Ĳ�ֵ
            //getClassVirtualMethodsMethodIdxSubFromIndex�����ֵ���㹤��
            int nBase = getClassVirtualMethodsBaseMethodIdxFromIndex(nIndex);
            int nSub = getClassVirtualMethodsMethodIdxSubFromIndex(nIndex, nFieldIndex);
            nFieldIdxDiffValue = nFieldIndex != 0 ? 
                nBase
                + nSub : nBase;
            const char* pMethodString = getMethodIdsStringFromIndex(nFieldIdxDiffValue);
            sprintf(result, "[%d]method_idx_diff:%s access_flags:%s code_off:%X", 
                i,
                pMethodString,
                p,
                getClassVirtualMethodsCodeOffValueIndex(pByte));
            delete[] (char*)p;
            delete[] (char*)pMethodString;
			break;
		}
		//ÿһ��fieldsռ3��leb128����
		pByte = getNextSTAddr(pByte, 3);
	}
	return result;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡ��pByteΪ��ַ��method_item�ṹ��field_idx_diff�ֶ�ֵ
                class_def_item->class_data_off_->
                virtual_methods_size->field_idx_diff�ֶ�ֵ,����һ��LEB128����
 * ��������: pByte ָ��Ŀ���ַ
 * ��������ֵ��field_idx_diff�ֶ�ֵ
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getClassVirtualMethodsFieldIdxDiffValueIndex(BYTE *pByte)
{
	return getClassDirectMethodsMethodIdxDiffValueIndex(pByte);
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡ��pByteΪ��ַ��method_item�ṹ��access_flags�ֶ�ֵ
                class_def_item->class_data_off_->
                virtual_methods_size->access_flags�ֶ�ֵ,����һ��LEB128����
 * ��������: pByte ָ��Ŀ���ַ
 * ��������ֵ��access_flags�ֶ�ֵ
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getClassVirtualMethodsAccessFlagsValueIndex(BYTE *pByte)
{
	return getClassDirectMethodsAccessFlagsValueIndex(pByte);
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡ��pByteΪ��ַ��method_item�ṹ��code_off�ֶ�ֵ
                class_def_item->class_data_off_->
                virtual_methods_size->code_off�ֶ�ֵ,����һ��LEB128����
 * ��������: pByte ָ��Ŀ���ַ
 * ��������ֵ��code_off�ֶ�ֵ
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getClassVirtualMethodsCodeOffValueIndex(BYTE *pByte)
{
	return getClassDirectMethodsCodeOffValueIndex(pByte);
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item[nIndex]->class_data_off_->
                virtual_methods_size[nVirtualIndex]->code_off�ֶ�ֵ,
                ����һ��LEB128���ݣ�ָ��CodeItem�ṹ���ļ��е�ƫ��
 * ��������: nIndex class�±�
                nVirtualIndex virtual�±�
 * ��������ֵ��code_off�ֶ�ֵ
 */
///////////////////////////////////////////////////////////////////////////
DWORD CMyDexObj::getClassVirtualMethodsCodeOffValueFromIndex(uint nIndex, uint nVirtualIndex)
{
    //��ȡvirtual_method_size_�ֶ�ֵ���������
    uint nvirtual_method_size = getClassClassDataVirtualMethodsSizeValueFromIndex(nIndex);
    //������һ�������ֶ�Ϊ0ʱ��������
    if (nvirtual_method_size == 0 || nVirtualIndex < 0 || nVirtualIndex > nvirtual_method_size)
    {
        return 0;
    }
    //��ȡvirtual_methods_size��Ӧ�Ľṹ�׵�ַ,����leb128���ݷֱ��ʾmethods_idx_diff,access_flags,code_off
    BYTE *pByte = getClassVirtualMethodsSTAddrFromIndex(nIndex);
    //Ŀ���ֶ���������Ԥ��ʱ���б���
    for (uint i = 0; i < nvirtual_method_size; i++)
    {
        if (i == nVirtualIndex)
        {
            return getClassVirtualMethodsCodeOffValueIndex(pByte);
        }
        //ÿһ��fieldsռ3��leb128����
        pByte = getNextSTAddr(pByte, 3);
    }
	return 0;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item->class_data_off_->
                virtual_methods_sizeָ��������׵�ַ,û���򷵻ؿ�ָ�룡����
 * ��������: nIndex class�±�
 * ��������ֵ��virtual_methods_sizeָ��������׵�ַ���߿�
 */
///////////////////////////////////////////////////////////////////////////
BYTE* CMyDexObj::getClassVirtualMethodsSTAddrFromIndex(uint nIndex)
{
	//���⴦��
	uint nSize = getClassClassDataVirtualMethodsSizeValueFromIndex(nIndex);
	if (nSize == 0)
	{
		return NULL;
	}
	//���������Class�ĵ�ַ
    PSTClassDataItem pCDI = getClassClassDataSTFileOffsetFromIndex(nIndex);
    if (!pCDI)
    {
        return NULL;
	}
    //�ṹ���׵�ַ+�ļ��׵�ַ
    pCDI = (PSTClassDataItem)(DWORD(pCDI) + getFileBeginAddr());
	//����4��leb��ʾ�ĸ����ֶε�����
	BYTE *pByte = getNextSTAddr((BYTE*)pCDI, 4);
	//����ǰ���м���static_fields����,ÿ��static_fields�ṹ��������LEB128����
	nSize = getClassClassDataStaticFieldsSizeValueFromIndex(nIndex) * 2;
	//����ǰ���м���instance_fields����ÿ��static_fields�ṹ��������LEB128����
	nSize += getClassClassDataInstanceFieldsSizeValueFromIndex(nIndex) * 2;
	//����ǰ���м���direct_method_fields����ÿ��static_fields�ṹ��������LEB128���ݣ�
	nSize += getClassClassDataDirectMethodsSizeValueFromIndex(nIndex) * 3;
	//��������LEB���ݾͶ���
	pByte = getNextSTAddr(pByte, nSize);
	return pByte;
}
//��ȡָ����VirtualMethodָ������ݽṹ��method_idx����
uint32_t CMyDexObj::getClassVirtualMethodsBaseMethodIdxFromIndex(uint nIndex)
{
    //��ȡ����׵�ַ
    BYTE *pByte = getClassVirtualMethodsSTAddrFromIndex(nIndex);
    if (!pByte)
    {
        return 0;
    }
    //�׵�ַ��Ϊleb128���͵�method_idx_diffֵ
    return readLeb128(pByte);
}
//��ȡָ����VirtualMethodָ������ݽṹ��method_idx����
uint32_t CMyDexObj::getClassVirtualMethodsMethodIdxSubFromIndex(uint nIndex, uint nMethodIndex)
{
    //��ȡ����׵�ַ
    BYTE *pByte = getClassVirtualMethodsSTAddrFromIndex(nIndex);
    if (!pByte)
    {
        return 0;
    }
    //����3��leb128����һ�ṹ
    pByte = getNextSTAddr(pByte, 3);
    int nSub = 0;
    //�ۼ�
    for (uint i = 1; i <= nMethodIndex; i++)
    {
        nSub += readLeb128(pByte);
        //�ƶ�����һ���ṹ��ַ
        pByte = getNextSTAddr(pByte, 3);
    }
    return nSub;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item->class_data_off_->
                virtual_methods_size->data_off_�Ƿ���Ҫ���
 * ��������: nIndex class�±�
 * ��������ֵ��data_off��Ϊ�շ���true,����false
 */
///////////////////////////////////////////////////////////////////////////
bool CMyDexObj::isClassVirturlMethodsNeedShowDataOffStringFromIndex(uint nIndex)
{
    //��ȡָ���±��µ�class_def_item->class_data_off_->virtual_methods_size��Ӧ���׵�ַ
    BYTE *pByte = getClassVirtualMethodsSTAddrFromIndex(nIndex);
    if(pByte == NULL)
        return false;

    //��Ӧ�ṹoff��Ϊ0��ʾ������Ч
    DWORD dwOff = getClassVirtualMethodsCodeOffValueIndex(pByte);
    return dwOff != 0;
}
//
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_item->class_data_off_->
                virtual_methods_size->data_off_ָ��Ľṹ�ļ�ƫ���׵�ַ
 * ��������: nIndex class�±�
 * ��������ֵ��data_off_ָ��Ľṹ�ļ�ƫ���׵�ַ���
 */
///////////////////////////////////////////////////////////////////////////
PSTCodeItem CMyDexObj::getClassVirtualMethodsDataOffSTFileOffsetFromeIndex(uint nIndex)
{
    //��ȡָ���±��µ�class_def_item->class_data_off_->virtual_methods_size��Ӧ���׵�ַ
    PSTCodeItem pCI = (PSTCodeItem)getClassVirtualMethodsSTAddrFromIndex(nIndex); 
    return pCI;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��data_off_�ֶ�ָ��ķ�����Ϣ�ַ���������ֵ��Ҫ�ֶ��ͷ�delete[]                 
 * ��������: dwOff CodeItem���ļ�ƫ��
 * ��������ֵ��
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
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡָ��class_def_itemָ��virtual_methods�µ�data_off_�ֶ�ָ��ķ����ṹ��Ϣ�ַ�����
                ����ֵ��Ҫ�ֶ��ͷ�delete[]                 
 * ��������: nIndex class�����±�
                nVirtualMethodIndex methods�±�
 * ��������ֵ��data_off_�ֶ�ָ��ķ����ṹ��Ϣ�ַ���
 */
/////////////////////////////////////////////////////////////////////////// 
const char* CMyDexObj::getClassVirtualMethodsDataOffStringFromIndex(uint nIndex, uint nVirtualMethodIndex)
{
	//��ȡ��Ӧ���µ�ָ��VirtualMethod�ṹ�µ�code_offֵ���伴ΪCodeItem�ṹ���ļ�ƫ��
	DWORD dwOff = getClassVirtualMethodsCodeOffValueFromIndex(nIndex, nVirtualMethodIndex);
    //getClassVirtualMethodsDataOffStringFromIndex�ڲ������ж�dwOff�Ƿ�ʱ�Ĵ���
	return getClassVirtualMethodsDataOffStringFromIndex(dwOff);
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡdata_off_�ṹ�µ�register_size_�ֶ�ֵ  
 * ��������: dwOff codeitem�ṹ���ļ�ƫ��
 * ��������ֵ��registers_size_�ֶ�ֵ
 */
/////////////////////////////////////////////////////////////////////////// 
uint16_t CMyDexObj::getClassVirtualMethodsDataOffRegisterSizeValueFromIndex(DWORD dwOff)
{
	//�������Ĳ���Ϊ0���򷵻�0
	if (dwOff == 0)
	{
		return 0;
	}
    PSTCodeItem pCI = (PSTCodeItem)(dwOff + getFileBeginAddr());
    return pCI->registers_size_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡdata_off_�ṹ�µ�ins_size_�ֶ�ֵ
 * ��������: dwOff codeitem�ṹ���ļ�ƫ��
 * ��������ֵ��ins_size_�ֶ�ֵ
 */
/////////////////////////////////////////////////////////////////////////// 
uint16_t CMyDexObj::getClassVirtualMethodsDataOffInsSizeValueFromIndex(DWORD dwOff)
{
	//�������Ĳ���Ϊ0���򷵻�0
	if (dwOff == 0)
	{
		return 0;
	}
    PSTCodeItem pCI = (PSTCodeItem)(dwOff + getFileBeginAddr());
    return pCI->ins_size_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡdata_off_�ṹ�µ�out_size_�ֶ�ֵ
 * ��������: dwOff codeitem�ṹ���ļ�ƫ��
 * ��������ֵ��out_size_�ֶ�ֵ
 */
/////////////////////////////////////////////////////////////////////////// 
uint16_t CMyDexObj::getClassVirtualMethodsDataOffOutsSizeValueFromIndex(DWORD dwOff)
{
	//�������Ĳ���Ϊ0���򷵻�0
	if (dwOff == 0)
	{
		return 0;
	}
    PSTCodeItem pCI = (PSTCodeItem)(dwOff + getFileBeginAddr());
    return pCI->outs_size_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡdata_off_�ṹ�µ�tries_size_�ֶ�ֵ
 * ��������: dwOff codeitem�ṹ���ļ�ƫ��
 * ��������ֵ��tries_size_�ֶ�ֵ
 */
/////////////////////////////////////////////////////////////////////////// 
uint16_t CMyDexObj::getClassVirtualMethodsDataOffTriesSizeValueFromIndex(DWORD dwOff)
{
	//�������Ĳ���Ϊ0���򷵻�0
	if (dwOff == 0)
	{
		return 0;
	}
    PSTCodeItem pCI = (PSTCodeItem)(dwOff + getFileBeginAddr());
    return pCI->tries_size_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡdata_off_�ṹ�µ�debug_info_off_�ֶ�ֵ
 * ��������: dwOff codeitem�ṹ���ļ�ƫ��
 * ��������ֵ��debug_info_off_�ֶ�ֵ
 */
/////////////////////////////////////////////////////////////////////////// 
uint32_t CMyDexObj::getClassVirtualMethodsDataOffDebugInfoOffValueFromIndex(DWORD dwOff)
{
	//�������Ĳ���Ϊ0���򷵻�0
	if (dwOff == 0)
	{
		return 0;
	}
    PSTCodeItem pCI = (PSTCodeItem)(dwOff + getFileBeginAddr());
    return pCI->debug_info_off_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡdata_off_�ṹ�µ�insns���ݴ�С��ʵ����WORD�ĸ���
 * ��������: dwOff codeitem�ṹ���ļ�ƫ��
 * ��������ֵ��insns���ݴ�С��ʵ����WORD�ĸ���
 */
/////////////////////////////////////////////////////////////////////////// 
uint32_t CMyDexObj::getClassVirtualMethodsDataOffInsnsSizeInCodeUnitsValueFromIndex(DWORD dwOff)
{
	//�������Ĳ���Ϊ0���򷵻�0
	if (dwOff == 0)
	{
		return 0;
	}
    PSTCodeItem pCI = (PSTCodeItem)(dwOff + getFileBeginAddr());
    return pCI->insns_size_in_code_units_;
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡdata_off_�ṹ�µ�insns�����ļ�ƫ�Ƶ�ַ
 * ��������: dwOff codeitem�ṹ���ļ�ƫ��
 * ��������ֵ��insns������ʼ��ַ
 */
///////////////////////////////////////////////////////////////////////////
WORD* CMyDexObj::getClassVirtualMethodsDataOffInsnsFileOffsetFromIndex(DWORD dwOff)
{
	//�������Ĳ���Ϊ0���򷵻�0
	if (dwOff == 0)
	{
		return 0;
	}
    PSTCodeItem pCI = (PSTCodeItem)(dwOff + getFileBeginAddr());
	DWORD dwAdd = (DWORD)&pCI->insns_;
	DWORD dwFile = getFileBeginAddr();
    return (WORD*)(dwAdd - dwFile);
}
///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡClassVirtualMethodsDataOffInsns�µĻ����룬����ֵ�ֶ��ͷ�
 * ��������: pSTCI �ļ�ƫ��ָ��
 * ��������ֵ��Insns�µĻ�����
 */
///////////////////////////////////////////////////////////////////////////
const char* CMyDexObj::getClassVirtualMethodsDataOffInsnsMachineCode(PSTCodeItem pSTCI)
{
    return getClassDirectMethodsDataOffInsnsMachineCode(pSTCI);
	
    //���code�ֽ��벻Ϊ��
	
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
//             //2���ֽڶ���
//             uint16_t code = pSTCI->insns_[i];
//             
//             sprintf(temp, " %02X %02X", (BYTE)(code & 0xff),
//                 (BYTE)((code >> 8) & 0xff));
//             strcat(result, temp);
//         }
// 	}
//     return result;
}