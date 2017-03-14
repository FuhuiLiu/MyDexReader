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
    const char* getShortyIdxStringFromIndex(uint nIdex); //��proto_id_item����ָ���±귽���ļ��򷵻�ֵ�������ַ���
    const char* getReturnTypeIdxStringFromIndex(uint nIndex); //��proto_id_itemָ���±귽���ķ��������ַ���
    const char* getParametersStringFromIndex(uint nIndex); //��proto_id_itemָ���±귽���Ĳ����б��ַ���,����ֵ��Ҫ�ֹ��ͷ�    
    DWORD getShortyIdxValueFromIndex(uint nIdex); //��ָ���±귽����ShortyIdx�ֶ�ֵ
    DWORD getReturnTypeIdxValueFromIndex(uint nIndex); //��ָ���±귽����ReturnTypeIdx�ֶ�ֵ 
    DWORD getParametersValueFromIndex(uint nIndex); //��ָ���±귽����Parameter�ֶ�ֵ

    bool initFieldIdItemST();        //��ʼ��field_id_item��Ҫ�ṹ
    bool ColletionFieldIdItem();     //�ռ�field_id_item��
    STFieldIdItem* getFieldIdSTFromId(uint nIndex);   //��field_id_listָ���±�Ľṹ�׵�ַ
    uint16_t getClassIdxValueFromId(uint nIndex);   //��MethodId�ṹ����class_idx_�ֶ�ֵ
    uint16_t getProtoIdxValueFromId(uint nIndex);   //��MethodId�ṹ����proto_idx_�ֶ�ֵ
    uint32_t getNameIdxValueFromId(uint nIndex);   //��MethodId�ṹ����name_idx_�ֶ�ֵ
    DWORD getFieldIdSizeFromSave();    //��ȡFieldIdSize����
	DWORD getFieldClassIdxValueFromIndex(uint nIndex); //��field_id_item����ָ���±��class_idx_�ֶ�ֵ
	DWORD getFieldTypeIdxValueFromIndex(uint nIndex); //��field_id_item����ָ���±��proto_idx_�ֶ�ֵ
	DWORD getFieldNameIdxValueFromIndex(uint nIndex); //��field_id_item����ָ���±��name_idx_�ֶ�ֵ
	const char* getFieldTypeIdxStringFromId(uint nIndex); //��field_id_item����ָ���±��type_idx_��ʾ���ַ���
	const char* getFieldClassIdxStringFromId(uint nIndex); //��field_id_item����ָ���±��class_idx_��ʾ���ַ���
	const char* getFieldNameIdxStringFromId(uint nIndex); //��field_id_item����ָ���±��name_idx_��ʾ���ַ���

    bool initMethodIdItemST();        //��ʼ��method_id_item��Ҫ�ṹ
    bool ColletionMethodIdItem();     //�ռ�method_id_item��
    STMethodIdItem* getMethodIdSTFromId(uint nIndex);   //��method_id_listָ���±�Ľṹ�׵�ַ
    DWORD getMethodIdSizeFromSave();    //��ȡMethodIdSize����
    void showMethodStringAt(uint nIndex);               //��ʾ�����ַ���
	const char* getMethodClassIdxStringFromIndex(uint nIndex); //��method_id_item����ָ���±귽�������ַ���
	const char* getMethodProtoIdxStringFromIndex(uint nIndex); //��method_id_item����ָ���±귽���ķ���ԭ���ַ���
	const char* getMethodNameIdxStringFromIndex(uint nIndex); //��method_id_item����ָ���±귽���ķ������ַ���
	uint16_t getMethodClassIdxValueFromIndex(uint nIndex); //��method_id_item����ָ���±��class_idx_�ֶ�ֵ
	uint16_t getMethodProtoIdxValueFromIndex(uint nIndex); //��method_id_item����ָ���±��proto_idx_�ֶ�ֵ
	uint32_t getMethodNameIdxValueFromIndex(uint nIndex); //��method_id_item����ָ���±��name_idx_�ֶ�ֵ

    bool initClassDefItemST();        //��ʼ��classdef_item��Ҫ�ṹ
    bool ColletionClassDefItem();     //�ռ�ClassDef_item��
    STClassDefItem* getClassDefSTFromId(uint nIndex);   //��ClassDef_listָ���±�Ľṹ�׵�ַ
    DWORD getClassDefSizeFromSave();    //��ȡClassDefSize����
    uint16_t getClassClassIdxValueFromIndex(uint nIndex);        //��ȡclass_def_item�±�ṹ�е�class_idx_�ֶ�ֵ
    uint16_t getClassPad1ValueFromIndex(uint nIndex);				//��ȡclass_def_item�±�ṹ�е�pad1_�ֶ�ֵ	
    uint32_t getClassAccessFlagsValueFromIndex(uint nIndex);        //��ȡclass_def_item�±�ṹ�е�access_flags_�ֶ�ֵ
    uint16_t getClassSuperclassIdxValueFromIndex(uint nIndex);        //��ȡclass_def_item�±�ṹ�е�superclass_idx_�ֶ�ֵ
    uint16_t getClassPad2ValueFromIndex(uint nIndex);				//��ȡclass_def_item�±�ṹ�е�pad2_�ֶ�ֵ
    uint32_t getClassInterfaceOffValueFromIndex(uint nIndex);        //��ȡclass_def_item�±�ṹ�е�interfaces_off�ֶ�ֵ
    uint32_t getClassSourceFileIdxValueFromIndex(uint nIndex);        //��ȡclass_def_item�±�ṹ�е�source_file_idx_�ֶ�ֵ
    uint32_t getClassAnnotationsOffValueFromIndex(uint nIndex);        //��ȡclass_def_item�±�ṹ�е�annotations_off_�ֶ�ֵ
    uint32_t getClassClassDataOffValueFromIndex(uint nIndex);        //��ȡclass_def_item�±�ṹ�е�class_data_off_�ֶ�ֵ
    uint32_t getClassStaticValuesOffValueFromIndex(uint nIndex);        //��ȡclass_def_item�±�ṹ�е�static_values_off_�ֶ�ֵ

	const char* getClassClassIdxStringFromIndex(uint nIndex);			//��ȡָ���±��ClassDef�ṹ�е�class_idx_���ַ���
	const char* getClassAccessFlagsStringFromIndex(uint nIndex);		//��ȡָ���±��ClassDef�ṹ�е�access_flags_���ַ���,����ֵ��Ҫ�ֶ��������ͷ�
	const char* getClassSuperClassIdxStringFromIndex(uint nIndex);		//��ȡָ���±��ClassDef�ṹ�е�superclass_idx_���ַ���
	const char* getClassSourceFileIdxStringFromIndex(uint nIndex);		//��ȡָ���±��ClassDef�ṹ�е�source_file_idx_���ַ���
    //������ӦClass�ṹ�е�class_annotations_off_�ж��Ƿ���Ҫ��������Ϣ
    bool isClassNeedShowAnnotationsString(uint nIndex);
    //��ȡ��ӦClass�ṹ�е�class_annotations_off_�ṹ����,����ֵ��Ҫ�ֶ��ͷ�
    const char* getClassAnnotationStringFromIndex(uint nIndex);
    //��ȡָ���±��STAnnotationsDirectoryItem�ṹָ��
    PSTAnnotationsDirectoryItem getClassAnnotationsDirectoryItemSTFromIndex(uint nIndex);
    
    //��ȡ��ӦClass�ṹ�е�class_annotations_off_�ṹ��class_annotations_off_�ֶ�ֵ
    uint32_t getClassAnnotationsClassAnnotationsOffValueFromIndex(uint nIndex);
    //��ȡ��ӦClass�ṹ�е�class_annotations_off_�ṹ��fields_size_�ֶ�ֵ
    uint32_t getClassAnnotationsFieldsSizeValueFromIndex(uint nIndex);
    //��ȡ��ӦClass�ṹ�е�class_annotations_off_�ṹ��methods_size_�ֶ�ֵ
    uint32_t getClassAnnotationsMethodsSizeValueFromIndex(uint nIndex);
    //��ȡ��ӦClass�ṹ�е�class_annotations_off_�ṹ��parameters_size_�ֶ�ֵ
    uint32_t getClassAnnotationsParametersSizeValueFromIndex(uint nIndex);

    
    //������ӦClass�ṹ�е�interfaces_off_�ж��Ƿ���Ҫ��������Ϣ
    bool isClassNeedShowInterfacesString(uint nIndex);
    //��ȡ��ӦClass�ṹ�е�class_annotations_off_�ṹ����,����ֵ��Ҫ�ֶ��ͷ�
    const char* getClassInterfacesStringFromIndex(uint nIndex);
    //��ȡָ��Class�±��interfaces_off_�ṹ�µ�list_�ṹָ��
    PSTTypeList getClassInterfaceListSTFromIndex(uint nIndex);   
    //��ȡָ��Class�±��interfaces_off_�ṹ�µ�list_�ṹ����
    uint32_t getClassInterfaceListSizeFromIndex(uint nIndex);

	//����class_def_item->class_data_off_�ֶ�ֵ�ж��Ƿ���Ҫ���
	bool isClassNeedShowClassDataString(uint nIndex);
    //��ȡ��ӦClass�ṹ�е�class_data_off_�ṹ����,����ֵ��Ҫ�ֶ��ͷ�
    const char* getClassClassDataStringFromIndex(uint nIndex);
	//��ȡָ��Class�ṹ�е�STClassDataItem�ṹָ��
	PSTClassDataItem getClassClassDataSTFromIndex(uint nIndex);
	//��ȡָ��class_def_item->class_data_off_->static_fields_size�ֶ�ֵ������LEB128��������
	uint32_t getClassClassDataStaticFieldsSizeValueFromIndex(uint nIndex);
	//��ȡָ��class_def_item->class_data_off_->instance_fields_size�ֶ�ֵ������LEB128��������
	uint32_t getClassClassDataInstanceFieldsSizeValueFromIndex(uint nIndex);
	//��ȡָ��class_def_item->class_data_off_->direct_methods_size�ֶ�ֵ������LEB128��������
	uint32_t getClassClassDataDirectMethodsSizeValueFromIndex(uint nIndex);
	//��ȡָ��class_def_item->class_data_off_->virtual_methods_size�ֶ�ֵ������LEB128��������
	uint32_t getClassClassDataVirtualMethodsSizeValueFromIndex(uint nIndex);
	//��ȡָ��class_def_item->class_data_off_->virtual_methods_size�ֶ�ʵ��ռ�õ��ֽڳ���
	uint32_t getClassClassDataStaticFieldsSizeLenFromIndex(uint nIndex);
	//��ȡָ��class_def_item->class_data_off_->instance_fields_size�ֶ�ʵ��ռ�õ��ֽڳ���
	uint32_t getClassClassDataInstanceFieldsSizeLenFromIndex(uint nIndex);
	//��ȡָ��class_def_item->class_data_off_->direct_methods_size�ֶ�ʵ��ռ�õ��ֽڳ���
	uint32_t getClassClassDataDirectMethodsSizeLenFromIndex(uint nIndex);
	//��ȡָ��class_def_item->class_data_off_->virtual_methods_size�ֶ�ʵ��ռ�õ��ֽڳ���
	uint32_t getClassClassDataVirtualMethodsSizeLenFromIndex(uint nIndex);

	//��ȡclass_def_item->class_data_off_���ֶ�����ָ������׵�ַ��������Ϊʵ�����ݵ�����
	BYTE *getClassClassDataAttributeAddrFromIndex(uint nIndex);

	//ָ��class_def_item->class_data_off_->static_fields_size�ֶ�ֵ�Ƿ�Ϊ0
	bool isClassNeedShowStaticFieldsStringFromIndex(uint nIndex);
	//��ȡָ��class_def_item->class_data_off_->static_fields_size�ֶε��ַ���,����ֵ��Ҫ�ֶ��ͷ�
	const char* getClassStaticFieldsStringFromIndex(uint nIndex, uint nFieldIndex);
	//��ȡָ��class_def_item->class_data_off_->static_fields->field_idx_diff�ֶ�ֵ,����һ��LEB128����
	DWORD getClassStaticFieldsFieldIdxDiffValueIndex(BYTE *pByte);
	//��ȡָ��class_def_item->class_data_off_->static_fields->access_flags�ֶ�ֵ,����һ��LEB128����
	DWORD getClassStaticFieldsAccessFlagsValueIndex(BYTE *pByte);
	//��ȡ��һ��FieldST��BYTE��ַ��Ĭ��2��LEB128����Ϊ��
	BYTE* getNextSTAddr(BYTE *pByte, int nLeb128Count = 2);
	
	//ָ��class_def_item->class_data_off_->instance_fields_size�ֶ�ֵ�Ƿ�Ϊ0
	bool isClassNeedShowInstanceFieldsStringFromIndex(uint nIndex);
	//��ȡָ��class_def_item->class_data_off_->instance_fields_size�ֶε��ַ���,����ֵ��Ҫ�ֶ��ͷ�
	const char* getClassInstanceFieldsStringFromIndex(uint nIndex, uint nFieldIndex);
	//��ȡָ��class_def_item->class_data_off_->instance_fields_size->field_idx_diff�ֶ�ֵ,����һ��LEB128����
	DWORD getClassInstanceFieldsFieldIdxDiffValueIndex(BYTE *pByte);
	//��ȡָ��class_def_item->class_data_off_->instance_fields_size->access_flags�ֶ�ֵ,����һ��LEB128����
	DWORD getClassInstanceFieldsAccessFlagsValueIndex(BYTE *pByte);
	//��ȡָ��class_def_item->class_data_off_->instance_fieldsָ������ݵ�ַ,û���򷵻ؿ�ָ�룡����
	BYTE* getClassInstanceFieldsAddrFromIndex(uint nIndex);
	
	//ָ��class_def_item->class_data_off_->direct_methods_size�ֶ�ֵ�Ƿ�Ϊ0
	bool isClassNeedShowDirectMethodsStringFromIndex(uint nIndex);
	//��ȡָ��class_def_item->class_data_off_->direct_methods_size�ֶε��ַ���,����ֵ��Ҫ�ֶ��ͷ�
	const char* getClassDirectMethodsStringFromIndex(uint nIndex, uint nFieldIndex);
	//��ȡָ��class_def_item->class_data_off_->direct_methods_size->field_idx_diff�ֶ�ֵ,����һ��LEB128����
	DWORD getClassDirectMethodsMethodIdxDiffValueIndex(BYTE *pByte);
	//��ȡָ��class_def_item->class_data_off_->direct_methods_size->access_flags�ֶ�ֵ,����һ��LEB128����
	DWORD getClassDirectMethodsAccessFlagsValueIndex(BYTE *pByte);
	//��ȡָ��class_def_item->class_data_off_->direct_methods_size->code_off�ֶ�ֵ,����һ��LEB128����
	DWORD getClassDirectMethodsCodeOffValueIndex(BYTE *pByte);
	//��ȡָ��class_def_item->class_data_off_->direct_methods_sizeָ������ݵ�ַ,û���򷵻ؿ�ָ�룡����
	BYTE* getClassDirectMethodsAddrFromIndex(uint nIndex);
	
	//ָ��class_def_item->class_data_off_->virtual_methods_size�ֶ�ֵ�Ƿ�Ϊ0
	bool isClassNeedShowVirtualMethodsStringFromIndex(uint nIndex);
	//��ȡָ��class_def_item->class_data_off_->virtual_methods_size�ֶε��ַ���,����ֵ��Ҫ�ֶ��ͷ�
	const char* getClassVirtualMethodsStringFromIndex(uint nIndex, uint nFieldIndex);
	//��ȡָ��class_def_item->class_data_off_->virtual_methods_size->field_idx_diff�ֶ�ֵ,����һ��LEB128����
	DWORD getClassVirtualMethodsFieldIdxDiffValueIndex(BYTE *pByte);
	//��ȡָ��class_def_item->class_data_off_->virtual_methods_size->access_flags�ֶ�ֵ,����һ��LEB128����
	DWORD getClassVirtualMethodsAccessFlagsValueIndex(BYTE *pByte);
	//��ȡָ��class_def_item->class_data_off_->virtual_methods_size->code_off�ֶ�ֵ,����һ��LEB128����
	DWORD getClassVirtualMethodsCodeOffValueIndex(BYTE *pByte);
	//��ȡָ��class_def_item->class_data_off_->virtual_methods_sizeָ������ݵ�ַ,û���򷵻ؿ�ָ�룡����
	BYTE* getClassVirtualMethodsAddrFromIndex(uint nIndex);

	//���ط��ʱ�־�ַ���������ֵ��Ҫ�ֶ�delete []
	const char* getClassAccessFlagsString(DWORD dwFlags);
	
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