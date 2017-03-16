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
    const char* getStringIdStringFromIndex(uint nIndex); //��string_id_listָ���±���ַ���
    BYTE *getStringIdItemAddrFromIndex(uint nIndex); //��ָ���±��item�׵�ַ
    DWORD getStringLenFromIndex(uint nIndex); //��ָ���±��ַ����ĳ���
    DWORD getStringFillOffFromIndex(uint nIndex); //��ָ���±��ַ������ļ�ƫ��
    bool ColletionStringIdItem();   //�ռ��ַ�����

    bool initTypeIdItemST();        //��ʼ��type_id_item��Ҫ�ṹ
    bool ColletionTypeIdItem();     //�ռ�type_id_item��
    const char* getTypeIdStringFromIndex(uint nIndex);   //��type_id_listָ���±���ַ���
    DWORD getTypeItemSize();        //��ȡtype_id_item����

    bool initProtoIdItemST();        //��ʼ��proto_id_item��Ҫ�ṹ
    bool ColletionProtoIdItem();     //�ռ�proto_id_item��
	//��proto_id_listָ���±��proto_id_item�ṹ�׵�ַ
    STProtoIdItem* getProtoIdsSTFromIndex(uint nProtoIdsIndex); 
	//��proto_id_listָ���±�ĺ���ԭ����Ϣ
    const char* getProtoIdStringFromIndex(uint nProtoIdsIndex);   
	//��ȡָ���±�parameters_offָ���TypeItemList�ṹ�ļ�ƫ�Ƶ�ַ������ز���offΪ0�򷵻�ֵΪ��
    STTypeItemList *getProtoIdsTypeListFromIndex(uint nProtoIdsIndex);        
	//��ȡָ���±귽���Ĳ����б��ֶ�ֵ
    DWORD getProtoIdsParametersOffValueFromIndex(uint nProtoIdsIndex);
	//��proto_id_item����ָ���±귽���ļ��򷵻�ֵ�������ַ���
    const char* getProtoIdsShortyIdxStringFromIndex(uint nProtoIdsIdex); 
    const char* getProtoIdsReturnTypeIdxStringFromIndex(uint nProtoIdsIndex); //��proto_id_itemָ���±귽���ķ��������ַ���
    const char* getProtoIdsParametersStringFromIndex(uint nProtoIdsIndex); //��proto_id_itemָ���±귽���Ĳ����б��ַ���,����ֵ��Ҫ�ֹ��ͷ�    
    DWORD getProtoIdsShortyIdxValueFromIndex(uint nProtoIdsIndex); //��ָ���±귽����ShortyIdx�ֶ�ֵ
    DWORD getProtoIdsReturnTypeIdxValueFromIndex(uint nProtoIdsIndex); //��ָ���±귽����ReturnTypeIdx�ֶ�ֵ 
    DWORD getProtoIdsParametersValueFromIndex(uint nProtoIdsIndex); //��ָ���±귽����Parameter�ֶ�ֵ

    bool initFieldIdItemST();        //��ʼ��field_id_item��Ҫ�ṹ
    bool ColletionFieldIdItem();     //�ռ�field_id_item��
	//��field_id_listָ���±�Ľṹ�׵�ַ
    STFieldIdItem* getFieldIdSTFromIndex(uint nIndex);   
    uint16_t getFieldIdsClassIdxValueFromIndex(uint nIndex);   //��MethodId�ṹ����ָ���±��field_id_item�ṹ��class_idx_�ֶ�ֵ
    uint16_t getFieldIdsProtoIdxValueFromIndex(uint nIndex);   //��MethodId�ṹ����ָ���±��field_id_item�ṹ��proto_idx_�ֶ�ֵ
    uint32_t getFieldIdsNameIdxValueFromIndex(uint nIndex);   //��MethodId�ṹ����ָ���±��field_id_item�ṹ��name_idx_�ֶ�ֵ
    DWORD getFieldIdSizeFromSave();    //��ȡFieldIdSize����
	DWORD getFieldClassIdxValueFromIndex(uint nIndex); //��field_id_item����ָ���±��class_idx_�ֶ�ֵ
	DWORD getFieldTypeIdxValueFromIndex(uint nIndex); //��field_id_item����ָ���±��proto_idx_�ֶ�ֵ
	DWORD getFieldNameIdxValueFromIndex(uint nIndex); //��field_id_item����ָ���±��name_idx_�ֶ�ֵ
	const char* getFieldTypeIdxStringFromIndex(uint nIndex); //��field_id_item����ָ���±��type_idx_��ʾ���ַ���
	const char* getFieldClassIdxStringFromIndex(uint nIndex); //��field_id_item����ָ���±��class_idx_��ʾ���ַ���
	const char* getFieldNameIdxStringFromIndex(uint nIndex); //��field_id_item����ָ���±��name_idx_��ʾ���ַ���

    bool initMethodIdItemST();        //��ʼ��method_id_item��Ҫ�ṹ
    bool ColletionMethodIdItem();     //�ռ�method_id_item��
    STMethodIdItem* getMethodIdSTFromIndex(uint nIndex);   //��method_id_listָ���±�Ľṹ�׵�ַ
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
    STClassDefItem* getClassDefSTFromId(uint nIndex);   //������Ϣ�б�(ClassDef_list)ָ���±�Ľṹָ��
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
    //��ȡ��ӦClass�ṹ�е�class_interfaces_off_�ṹ����,����ֵ��Ҫ�ֶ��ͷ�
    const char* getClassInterfacesStringFromIndex(uint nIndex);
    //��ȡָ��Class�±��interfaces_off_�ֶ�ָ���type_item_list�ṹ���ļ��е�ƫ��
    PSTTypeItemList getClassInterfaceListSTFileOffsetFromIndex(uint nIndex);   
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
	//��ȡָ��class_def_item->class_data_off_->virtual_methods_size�ֶ�ֵ��
	//����LEB128�������ݱ�ʾ����ຬ�е�virtual_method����
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
    //��ȡָ��class_def_item->class_data_off_->virtual_methods_size->code_off�ֶ�ֵ,����һ��LEB128����
	DWORD getClassDirectMethodsCodeOffValueIndex(uint nIndex, uint nItemIndex);
	//��ȡָ��class_def_item->class_data_off_->direct_methods_sizeָ������ݵ�ַ,û���򷵻ؿ�ָ�룡����
	BYTE* getClassDirectMethodsAddrFromIndex(uint nIndex);
    //��ȡָ��class_def_item->class_data_off_->direct_methods_size->data_off_�Ƿ���Ҫ���
    bool isClassDirectMethodsNeedShowDataOffStringFromIndex(uint nIndex);
    //��ȡָ��class_def_item->class_data_off_->direct_methods_size->data_off_ָ��ṹ������
    const char* getClassDirectMethodsDataOffStringFromIndex(DWORD dwOff);
    //��ȡָ�����±�ָ��DirectMethod��ָ��ṹ������
    const char* getClassDirectMethodsDataOffStringFromIndex(uint nClassIndex, uint nDirectMethodIndex);
    //��ȡָ��class_def_item->class_data_off_->direct_methods_size->data_off_ָ��ṹ�׵�ַ
    PSTCodeItem getClassDirectMethodsDataOffSTFromeIndex(uint nIndex);
    //��ȡdata_off_�ṹ�µ�register_size_�ֶ�ֵ
    uint16_t getClassDirectMethodsDataOffRegisterSizeValueFromIndex(DWORD dwOff);
    //��ȡdata_off_�ṹ�µ�ins_size_�ֶ�ֵ
    uint16_t getClassDirectMethodsDataOffInsSizeValueFromIndex(DWORD dwOff);
    //��ȡdata_off_�ṹ�µ�out_size_�ֶ�ֵ
    uint16_t getClassDirectMethodsDataOffOutsSizeValueFromIndex(DWORD dwOff);
    //��ȡdata_off_�ṹ�µ�tries_size_�ֶ�ֵ
    uint16_t getClassDirectMethodsDataOffTriesSizeValueFromIndex(DWORD dwOff);
    //��ȡdata_off_�ṹ�µ�debug_info_off_�ֶ�ֵ
    uint32_t getClassDirectMethodsDataOffDebugInfoOffValueFromIndex(DWORD dwOff);
    //��ȡdata_off_�ṹ�µ�insns���ݴ�С��ʵ����WORD�ĸ���
    uint32_t getClassDirectMethodsDataOffInsnsSizeInCodeUnitsValueFromIndex(DWORD dwOff);
    //��ȡdata_off_�ṹ�µ�insns�����ļ�ƫ����ʼ��ַ
    WORD* getClassDirectMethodsDataOffInsnsFileOffsetFromIndex(DWORD dwOff);
    //��ȡClassDirectMethodsDataOffInsns�µĻ����룬����ֵ�ֶ��ͷ�
    const char* getClassDirectMethodsDataOffInsnsMachineCode(PSTCodeItem pSTCIFileOffset);
    //��ȡָ��classָ��DirectMethods�Ļ����룬����ֵ�ֶ��ͷ�
    const char* getClassDirectMethodsDataOffInsnsMachineCode(uint nClassIndex, uint nDirectMethodIndex);
	
	//ָ��class_def_item->class_data_off_->virtual_methods_size�ֶ�ֵ�Ƿ�Ϊ0
	bool isClassNeedShowVirtualMethodsStringFromIndex(uint nIndex);
	//��ȡָ��class_def_item->class_data_off_->virtual_methods_size�ֶε��ַ���,����ֵ��Ҫ�ֶ��ͷ�
	const char* getClassVirtualMethodsStringFromIndex(uint nIndex, uint nVirtualMethodIndex);
	//��ȡָ��class_def_item->class_data_off_->virtual_methods_size->field_idx_diff�ֶ�ֵ,����һ��LEB128����
	DWORD getClassVirtualMethodsFieldIdxDiffValueIndex(BYTE *pByte);
	//��ȡָ��class_def_item->class_data_off_->virtual_methods_size->access_flags�ֶ�ֵ,����һ��LEB128����
	DWORD getClassVirtualMethodsAccessFlagsValueIndex(BYTE *pByte);
	//��ȡָ��class_def_item->class_data_off_->virtual_methods_size->code_off�ֶ�ֵ,����һ��LEB128����
    DWORD getClassVirtualMethodsCodeOffValueIndex(BYTE *pByte);
    //��ȡָ��class_def_item->class_data_off_->virtual_methods_size->code_off�ֶ�ֵ,����һ��LEB128����
	DWORD getClassVirtualMethodsCodeOffValueFromIndex(uint nIndex, uint nItemIndex);
	//��ȡָ��class_def_item->class_data_off_->virtual_methods_sizeָ������ݵ�ַ,û���򷵻ؿ�ָ�룡����
    BYTE* getClassVirtualMethodsAddrFromIndex(uint nIndex);
    //��ȡָ��class_def_item->class_data_off_->virtual_methods_size->data_off_�Ƿ���Ҫ���
    bool isClassVirturlMethodsNeedShowDataOffStringFromIndex(uint nIndex);
    //��ȡָ��data_off_�ֶ�ָ��ķ�����Ϣ�ַ���������ֵ��Ҫ�ֶ��ͷ�delete[]   
    const char* getClassVirtualMethodsDataOffStringFromIndex(DWORD dwOff);
    //��ȡָ��class_def_itemָ��virtual_methods�µ�data_off_�ֶ�ָ��ķ�����Ϣ�ַ���������ֵ��Ҫ�ֶ��ͷ�delete[]   
    const char* getClassVirtualMethodsDataOffStringFromIndex(uint nIndex, uint nVirtualMethodIndex);
    //��ȡָ��class_def_item->class_data_off_->virtual_methods_size->data_off_ָ��ṹ�׵�ַ
    PSTCodeItem getClassVirtualMethodsDataOffSTFromeIndex(uint nIndex);
    //��ȡdata_off_�ṹ�µ�register_size_�ֶ�ֵ
    uint16_t getClassVirtualMethodsDataOffRegisterSizeValueFromIndex(DWORD dwOff);
    //��ȡdata_off_�ṹ�µ�ins_size_�ֶ�ֵ
    uint16_t getClassVirtualMethodsDataOffInsSizeValueFromIndex(DWORD dwOff);
    //��ȡdata_off_�ṹ�µ�out_size_�ֶ�ֵ
    uint16_t getClassVirtualMethodsDataOffOutsSizeValueFromIndex(DWORD dwOff);
    //��ȡdata_off_�ṹ�µ�tries_size_�ֶ�ֵ
    uint16_t getClassVirtualMethodsDataOffTriesSizeValueFromIndex(DWORD dwOff);
    //��ȡdata_off_�ṹ�µ�debug_info_off_�ֶ�ֵ
    uint32_t getClassVirtualMethodsDataOffDebugInfoOffValueFromIndex(DWORD dwOff);
    //��ȡdata_off_�ṹ�µ�insns���ݴ�С��ʵ����WORD�ĸ���
    uint32_t getClassVirtualMethodsDataOffInsnsSizeInCodeUnitsValueFromIndex(DWORD dwOff);
    //��ȡdata_off_�ṹ�µ�insns�����ļ�ƫ����ʼ��ַ
    WORD* getClassVirtualMethodsDataOffInsnsFileOffsetFromIndex(DWORD dwOff);
    //��ȡClassVirtualMethodsDataOffInsns�µĻ����룬����ֵ�ֶ��ͷ�
    const char* getClassVirtualMethodsDataOffInsnsMachineCode(PSTCodeItem pSTCI);


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