#if !defined(AFX_MYDEXOBJ_H__20170226_)
#define AFX_MYDEXOBJ_H__20170226_

#include "DexFile.h"
//#include <WINDOWS.H>
#include <AFX.H>

class CMyDexObj
{
public:
    CMyDexObj();      //���ļ�ָ���ʼ��
    bool isDexFile();
    bool init(void *pContext);
    ~CMyDexObj();
    //uint32_t getOriginFileSize();         //��ȡ�����ļ���С
    DWORD getFileBeginAddr();       //��ȡ�ļ����ڴ���׵�ַ

    char* getMagic();               //��ȡMagic
    uint32_t getChecksum();         //��ȡ�ļ�У����
    BYTE* getSignature();           //��ȡǩ����Ϣ
    uint32_t getFileSize();         //��ȡDEX HEADER��ָʾ���ļ���С
    uint32_t getHeaderSize();       //��ȡHEADER�ṹ��С
    uint32_t getEndianTag();        //��ȡ��Сβ��־
    uint32_t getLinkSize();         // unused
    uint32_t getLinkOff();          //
    uint32_t getMapOff();           //
    uint32_t getStringIdsSize();    // ����Header�ṹ�е�StringIdsSize
    uint32_t getStringIdsOff();     // file offset of StringIds array
    uint32_t getTypeIdsSize();      // number of TypeIds, we don't support more than 65535
    uint32_t getTypeIdsOff();       // file offset of TypeIds array
    uint32_t getProtoIdsSize();     // number of ProtoIds, we don't support more than 65535
    uint32_t getProtoIdsOff();      // file offset of ProtoIds array
    uint32_t getFieldIdsSize();     // number of FieldIds
    uint32_t getFieldIdsOff();      // file offset of FieldIds array
    uint32_t getMethodIdsSize();    // number of MethodIds
    uint32_t getMethodIdsOff();     // file offset of MethodIds array
    uint32_t getClassDefsSize();    // number of ClassDefs
    uint32_t getClassDefsOff();     // file offset of ClassDef array
    uint32_t getDataSize();         // unused
    uint32_t getDataOff();          // unused

    const STMapInfo* getMapInfo();  //��map_list�ṹ����
    //����MapItem���鷵��ָ�����ͽṹ���ļ�ƫ��
    STMapItem * getMapItemWithType(EMMapItemType type); 
    uint getMapItemSize();     //��ȡMapItem����

    bool initStringItemInfo();  //��ʼ��StringItem�������
    DWORD getStringItemSize();  //��ȡMapItem�ṹ��StringItem����
    const char* getStringIdStringFromId(uint nIndex); //��string_id_listָ���±���ַ���
    BYTE *getStringIdItemAddrFromId(uint nIndex); //��ָ���±��item�׵�ַ
    DWORD getStringLenFromIndex(uint nIndex); //��ָ���±��ַ����ĳ���
    DWORD getStringFillOffFromIndex(uint nIndex); //��ָ���±��ַ������ļ�ƫ��
    bool ColletionStringIdItem();   //�ռ��ַ�����

    bool initTypeIdItemST();        //��ʼ��type_id_item��Ҫ�ṹ
    bool ColletionTypeIdItem();     //�ռ�type_id_item��
    const char* getTypeIdStringFromId(uint nIndex);   //��type_id_listָ���±���ַ���
    DWORD getTypeItemSize();        //��ȡtype_id_item����

    bool initProtoIdItemST();        //��ʼ��proto_id_item��Ҫ�ṹ
    bool ColletionProtoIdItem();     //�ռ�proto_id_item��
    STProtoIdItem* getProtoIdSTFromId(uint nIndex);   //��proto_id_listָ���±�Ľṹ�׵�ַ
    const char* getProtoIdStringFromId(uint nIndex);   //��proto_id_listָ���±�ĺ���ԭ����Ϣ
    STTypeList *getTypeList(uint nIndex);              //��ȡָ���±귽����TypeList�ṹ��ַ
    DWORD getParametersOffFromIndex(uint nIndex);      //��ȡָ���±귽���Ĳ����б��ֶ�ֵ
    const char* getShortyIdxStringFromIndex(uint nIdex); //��ָ���±귽���ļ��򷵻�ֵ�������ַ���
    const char* getReturnTypeIdxStringFromIndex(uint nIndex); //��ָ���±귽���ķ��������ַ���
    const char* getParametersStringFromIndex(uint nIndex); //��ָ���±귽���Ĳ����б��ַ���,����ֵ��Ҫ�ֹ��ͷ�    
    DWORD getShortyIdxValueFromIndex(uint nIdex); //��ָ���±귽����ShortyIdx�ֶ�ֵ
    DWORD getReturnTypeIdxValueFromIndex(uint nIndex); //��ָ���±귽����ReturnTypeIdx�ֶ�ֵ 
    DWORD getParametersValueFromIndex(uint nIndex); //��ָ���±귽����Parameter�ֶ�ֵ


    bool initFieldIdItemST();        //��ʼ��field_id_item��Ҫ�ṹ
    bool ColletionFieldIdItem();     //�ռ�field_id_item��
    STFieldIdItem* getFieldIdSTFromId(uint nIndex);   //��field_id_listָ���±�Ľṹ�׵�ַ
    DWORD getFieldIdSizeFromSave();    //��ȡFieldIdSize����

    bool initMethodIdItemST();        //��ʼ��method_id_item��Ҫ�ṹ
    bool ColletionMethodIdItem();     //�ռ�method_id_item��
    STMethodIdItem* getMethodIdSTFromId(uint nIndex);   //��method_id_listָ���±�Ľṹ�׵�ַ
    DWORD getMethodIdSizeFromSave();    //��ȡMethodIdSize����
    void showMethodStringAt(uint nIndex);               //��ʾ�����ַ���

    bool initClassDefItemST();        //��ʼ��classdef_item��Ҫ�ṹ
    bool ColletionClassDefItem();     //�ռ�ClassDef_item��
    STClassDefItem* getClassDefSTFromId(uint nIndex);   //��ClassDef_listָ���±�Ľṹ�׵�ַ
    DWORD getClassDefSizeFromSave();    //��ȡClassDefSize����
    //TypeList* getInterfaceOff();        //��ȡclass_def_item�ṹ�е�interfaces_off
protected:
private:
    void *m_pNew;
    STHeader *m_pHeader;            //���Headerָ��
    STMapInfo *m_pMapInfo;          //ָ��map_list_type�ĵ�ַ=ͷ�ļ���ַ+map_off��ƫ��
    STMapItem *m_pMapItem;          //ָ��MapItem��ʼָ��
    uint m_nMapItemSize;            //MapItem����

    DWORD m_nStringIdItemSize;          //StringIdItem����
    STStringIdItem *m_pStringItem;      //StringIdItemָ��

    DWORD m_nTypeIdItemSize;                    //TypeIdItem����
    STTypeIdItem *m_pTypeIdItem;                //TypeIdItemָ��

    DWORD m_nProtoIdItemSize;                   //ProtoIdItem����
    STProtoIdItem *m_pProtoIdItem;              //ProtoIdItemָ��

    DWORD m_nFieldIdItemSize;                   //FieldIdItem����
    STFieldIdItem *m_pFieldIdItem;              //FieldIdItemָ��
    
    DWORD m_nMethodIdItemSize;                  //MethodIdItem����
    STMethodIdItem *m_pMethodIdItem;            //MethodIdItemָ��

    DWORD m_nClassDefItemSize;                  //ClassDefItem����
    STClassDefItem *m_pClassDefItem;            //ClassDefItemָ��
};

#endif