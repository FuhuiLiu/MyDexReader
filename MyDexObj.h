#if !defined(AFX_MYDEXOBJ_H__20170226_)
#define AFX_MYDEXOBJ_H__20170226_

#include "DexFile.h"
//#include <WINDOWS.H>
#include <AFX.H>

class CMyDexObj
{
public:
    CMyDexObj();      //用文件指针初始化
    bool isDexFile();
    bool init(void *pContext);
    ~CMyDexObj();
    //uint32_t getOriginFileSize();         //获取整个文件大小
    DWORD getFileBeginAddr();       //获取文件在内存的首地址

    char* getMagic();               //获取Magic
    uint32_t getChecksum();         //获取文件校验码
    BYTE* getSignature();           //获取签名信息
    uint32_t getFileSize();         //获取DEX HEADER中指示的文件大小
    uint32_t getHeaderSize();       //获取HEADER结构大小
    uint32_t getEndianTag();        //获取大小尾标志
    uint32_t getLinkSize();         // unused
    uint32_t getLinkOff();          //
    uint32_t getMapOff();           //
    uint32_t getStringIdsSize();    // 返回Header结构中的StringIdsSize
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

    const STMapInfo* getMapInfo();  //拿map_list结构数据
    //遍历MapItem数组返回指定类型结构的文件偏移
    STMapItem * getMapItemWithType(EMMapItemType type); 
    uint getMapItemSize();     //获取MapItem个数

    bool initStringItemInfo();  //初始化StringItem相关数据
    DWORD getStringItemSize();  //获取MapItem结构中StringItem个数
    const char* getStringIdStringFromId(uint nIndex); //拿string_id_list指定下标的字符串
    BYTE *getStringIdItemAddrFromId(uint nIndex); //拿指定下标的item首地址
    DWORD getStringLenFromIndex(uint nIndex); //拿指定下标字符串的长度
    DWORD getStringFillOffFromIndex(uint nIndex); //拿指定下标字符串的文件偏移
    bool ColletionStringIdItem();   //收集字符串表

    bool initTypeIdItemST();        //初始化type_id_item必要结构
    bool ColletionTypeIdItem();     //收集type_id_item表
    const char* getTypeIdStringFromId(uint nIndex);   //拿type_id_list指定下标的字符串
    DWORD getTypeItemSize();        //获取type_id_item数量

    bool initProtoIdItemST();        //初始化proto_id_item必要结构
    bool ColletionProtoIdItem();     //收集proto_id_item表
    STProtoIdItem* getProtoIdSTFromId(uint nIndex);   //拿proto_id_list指定下标的结构首地址
    const char* getProtoIdStringFromId(uint nIndex);   //拿proto_id_list指定下标的函数原型信息
    STTypeList *getTypeList(uint nIndex);              //获取指定下标方法的TypeList结构地址
    DWORD getParametersOffFromIndex(uint nIndex);      //获取指定下标方法的参数列表字段值
    const char* getShortyIdxStringFromIndex(uint nIdex); //拿指定下标方法的极简返回值跟参数字符串
    const char* getReturnTypeIdxStringFromIndex(uint nIndex); //拿指定下标方法的返回类型字符串
    const char* getParametersStringFromIndex(uint nIndex); //拿指定下标方法的参数列表字符串,返回值需要手工释放    
    DWORD getShortyIdxValueFromIndex(uint nIdex); //拿指定下标方法的ShortyIdx字段值
    DWORD getReturnTypeIdxValueFromIndex(uint nIndex); //拿指定下标方法的ReturnTypeIdx字段值 
    DWORD getParametersValueFromIndex(uint nIndex); //拿指定下标方法的Parameter字段值


    bool initFieldIdItemST();        //初始化field_id_item必要结构
    bool ColletionFieldIdItem();     //收集field_id_item表
    STFieldIdItem* getFieldIdSTFromId(uint nIndex);   //拿field_id_list指定下标的结构首地址
    DWORD getFieldIdSizeFromSave();    //获取FieldIdSize个数

    bool initMethodIdItemST();        //初始化method_id_item必要结构
    bool ColletionMethodIdItem();     //收集method_id_item表
    STMethodIdItem* getMethodIdSTFromId(uint nIndex);   //拿method_id_list指定下标的结构首地址
    DWORD getMethodIdSizeFromSave();    //获取MethodIdSize个数
    void showMethodStringAt(uint nIndex);               //显示方法字符串

    bool initClassDefItemST();        //初始化classdef_item必要结构
    bool ColletionClassDefItem();     //收集ClassDef_item表
    STClassDefItem* getClassDefSTFromId(uint nIndex);   //拿ClassDef_list指定下标的结构首地址
    DWORD getClassDefSizeFromSave();    //获取ClassDefSize个数
    //TypeList* getInterfaceOff();        //获取class_def_item结构中的interfaces_off
protected:
private:
    void *m_pNew;
    STHeader *m_pHeader;            //存放Header指针
    STMapInfo *m_pMapInfo;          //指向map_list_type的地址=头文件地址+map_off的偏移
    STMapItem *m_pMapItem;          //指向MapItem起始指针
    uint m_nMapItemSize;            //MapItem个数

    DWORD m_nStringIdItemSize;          //StringIdItem个数
    STStringIdItem *m_pStringItem;      //StringIdItem指针

    DWORD m_nTypeIdItemSize;                    //TypeIdItem个数
    STTypeIdItem *m_pTypeIdItem;                //TypeIdItem指针

    DWORD m_nProtoIdItemSize;                   //ProtoIdItem个数
    STProtoIdItem *m_pProtoIdItem;              //ProtoIdItem指针

    DWORD m_nFieldIdItemSize;                   //FieldIdItem个数
    STFieldIdItem *m_pFieldIdItem;              //FieldIdItem指针
    
    DWORD m_nMethodIdItemSize;                  //MethodIdItem个数
    STMethodIdItem *m_pMethodIdItem;            //MethodIdItem指针

    DWORD m_nClassDefItemSize;                  //ClassDefItem个数
    STClassDefItem *m_pClassDefItem;            //ClassDefItem指针
};

#endif