#include "StdAfx.h"
#include "MyDexShowUtils.h"

void MyDexShowUtils::EnterLine() { printf("\r\n"); }

void xxx(const char *p)
{
    printf("\r\n\r\n-------------------%s-------------------\r\n", p);
}

void MyDexShowUtils::MsgStart(const char* pstr)
{
    printf("\r\n\r\n-------------------%s-------------------\r\n", pstr);
}
void MyDexShowUtils::MsgEnd(const char* pstr)
{
    printf("-------------------%s-------------------\r\n\r\n", pstr);
}


MyDexShowUtils::MyDexShowUtils(): 
    m_FileObj(NULL), m_pDexObj(NULL), m_pNewAddr(NULL)
{}

bool MyDexShowUtils::init(const char* pDexFilePath)
{
    bool bRet = false;
    m_FileObj = new CMyFileObj();
    BOOL bOpenFileResult = m_FileObj->MyOpenFile(pDexFilePath); //"classes.dex"
    DWORD nFileSize = m_FileObj->MyGetFileSize();
    if (bOpenFileResult)
    {
        /*        MyPrintf("�ļ��򿪳ɹ�!!!");*/
        m_pNewAddr = new char[nFileSize];
        DWORD dwRead = m_FileObj->MyReadFile(m_pNewAddr, nFileSize);
        m_pDexObj = new CMyDexObj();
        if(m_pDexObj->init(m_pNewAddr))
            bRet = true;
        STHeader *pH = NULL;
        DWORD dwDexFileSize = m_pDexObj->getFileSize();
        DWORD dwFileSizeFileObj = m_FileObj->MyGetFileSize();

        printf("DexHead[%X] FileSize[%X] File Size: %s\r\n", 
            dwDexFileSize, dwFileSizeFileObj,
            dwDexFileSize == dwFileSizeFileObj ? 
            "Match!" : "un Match!");
        DWORD dwMapOff = m_pDexObj->getMapOff();
        int nMapSize = m_pDexObj->getMapItemSize();
        DWORD dwMapTo = dwMapOff + nMapSize * 0xc + sizeof(nMapSize);
        printf("dwMapTo:%X dwFileSizeFileObj:%X %s\r\n", 
            dwMapTo,
            dwFileSizeFileObj,
            dwMapTo == dwFileSizeFileObj ? "Dex Noral" : "Dex been Edit!");
        printf("[%X]Magic: %c%c%c%c%c%c\r\n", &pH->magic_, 
            m_pDexObj->getMagic()[0], m_pDexObj->getMagic()[1],
            m_pDexObj->getMagic()[2], /*m_pDexObj->getMagic()[3], */
            m_pDexObj->getMagic()[4], m_pDexObj->getMagic()[5], 
            m_pDexObj->getMagic()[6]);
        printf("[%X]Checksum: 0x%Xh\r\n", &pH->checksum_, m_pDexObj->getChecksum());
        printf("[%X]Signature: ", &pH->signature_);
        showSignature();
        EnterLine();
        printf("[%X]FileSize: 0x%Xh\r\n", &pH->file_size_, m_pDexObj->getFileSize());
        printf("[%X]HeaderSize: 0x%Xh\r\n", &pH->header_size_, m_pDexObj->getHeaderSize());
        printf("[%X]EndianTag: 0x%Xh\r\n", &pH->endian_tag_, m_pDexObj->getEndianTag());
        printf("[%X]LinkSize: 0x%Xh\r\n", &pH->link_size_, m_pDexObj->getLinkSize());
        printf("[%X]LinkOff: 0x%Xh\r\n", &pH->link_off_, m_pDexObj->getLinkOff());
        printf("[%X]MapOff: 0x%Xh\r\n", &pH->map_off_, m_pDexObj->getMapOff());
        printf("[%X]StringIdsSize: 0x%Xh\r\n", &pH->string_ids_size_, m_pDexObj->getStringIdsSize());
        printf("[%X]StringIdsOff: 0x%Xh\r\n", &pH->string_ids_off_, m_pDexObj->getStringIdsOff());
        printf("[%X]TypeIdsSize: 0x%Xh\r\n", &pH->type_ids_size_, m_pDexObj->getTypeIdsSize());
        printf("[%X]TypeIdsOff: 0x%Xh\r\n", &pH->type_ids_off_, m_pDexObj->getTypeIdsOff());
        printf("[%X]ProtoIdsSize: 0x%Xh\r\n", &pH->proto_ids_size_, m_pDexObj->getProtoIdsSize());
        printf("[%X]ProtoIdsOff: 0x%Xh\r\n", &pH->proto_ids_off_, m_pDexObj->getProtoIdsOff());
        printf("[%X]FieldIdsSize: 0x%Xh\r\n", &pH->field_ids_size_, m_pDexObj->getFieldIdsSize());
        printf("[%X]FieldIdsOff: 0x%Xh\r\n", &pH->field_ids_off_, m_pDexObj->getFieldIdsOff());
        printf("[%X]MethodIdsSize: 0x%Xh\r\n", &pH->method_ids_size_, m_pDexObj->getMethodIdsSize());
        printf("[%X]MethodIdsOff: 0x%Xh\r\n", &pH->method_ids_off_, m_pDexObj->getMethodIdsOff());
        printf("[%X]ClassDefsSize: 0x%Xh\r\n", &pH->class_defs_size_, m_pDexObj->getClassDefsSize());
        printf("[%X]ClassDefsOff: 0x%Xh\r\n", &pH->class_defs_off_, m_pDexObj->getClassDefsOff());
        printf("[%X]DataSize: 0x%Xh\r\n", &pH->data_size_, m_pDexObj->getDataSize());
        printf("[%X]DataOff: 0x%Xh\r\n", &pH->data_off_, m_pDexObj->getDataOff());
        
        //���MapItem����ֶ���Ϣ
        STMapInfo* mapinfo = (STMapInfo* )m_pDexObj->getMapInfo();
        uint nMapItemSize = mapinfo->m_nSize;
        
        STMapItem *pMi = &mapinfo->m_MapItem[0];
        printf("\r\n\t\tmap_off -> dex_map_list:\r\n");
        printf("%-5s %-32s %-5s %5s\r\n", "Index", "ItemName", "Size", "Offset");
        for (uint i = 0; i < nMapItemSize; i++)
        {
            printf("[%2d]: %-32s %4X  %-5X\r\n", i, getMapItemName(pMi[i].type_), pMi[i].size_, pMi[i].offset_);
        }
    }

    return bRet;
}

void MyDexShowUtils::showSignature()
{
    BYTE *pSignature = m_pDexObj->getSignature();
    if (pSignature == NULL)
    {
        pf("pSignature == NULL\r\n");
    }
    for (int i = 0; i < kSha1DigestSize; i++)
    {
        printf("%X", *(pSignature++));
    }
}

void MyDexShowUtils::showAllString()   //��ʾ�����ַ���
{
    MsgStart("AllString");
    DWORD dwStringItemSize = m_pDexObj->getStringItemSize();
    for (DWORD i = 0; i < dwStringItemSize; i++)
    {        
        printf("%d pStrLen[%X]-> %x ==>%s\r\n", i, 
            m_pDexObj->getStringLenFromIndex(i), //LEBʵ�����ݴ�С
            m_pDexObj->getStringFillOffFromIndex(i), //�ļ�ƫ��
            m_pDexObj->getStringIdStringFromId(i));
    }
    MsgEnd("AllString");
}

void MyDexShowUtils::showAllType()   //��ʾtype�ַ���
{
    MsgStart("AllType");
    DWORD dwTypeItemSize = m_pDexObj->getTypeItemSize();
    for (DWORD i = 0; i < dwTypeItemSize; i++)
    {        
        printf("%d ==>%s\r\n", i, m_pDexObj->getTypeIdStringFromId(i));
    }
    MsgEnd("AllType");
}

void MyDexShowUtils::showAllProto()  //��ʾ����proto��Ϣ
{
    MsgStart("AllProto");
    DWORD dwProtoItemSize = m_pDexObj->getProtoIdsSize();
    for (DWORD i = 0; i < dwProtoItemSize; i++)
    {        
        STProtoIdItem *pST = NULL;
        //��ȡ���±����͵ĵ�ַ
        pST = m_pDexObj->getProtoIdSTFromId(i);
        ASSERT(pST != NULL);
        printf("[%d]: shorty_idx: %s return_type_idx: %s ",
            i, m_pDexObj->getStringIdStringFromId(pST->shorty_idx_), 
            m_pDexObj->getTypeIdStringFromId(pST->return_type_idx_));//
        const char* pstr = m_pDexObj->getParametersStringFromIndex(i);
        printf("%s\r\n", pstr);
        delete[] (char*)pstr;
        pstr = m_pDexObj->getProtoIdStringFromId(i);
        printf("\tProtoIdString: %s\r\n", pstr);
        delete[] (char*)pstr;
    }
    MsgEnd("AllProto");
}