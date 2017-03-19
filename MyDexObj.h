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

    //��ʼ��StringItem�������
    bool initStringItemInfo();  
    //��ȡMapItem�ṹ��StringItem����
    DWORD getStringItemSize();  
    //��string_id_listָ���±���ַ���
    const char* getStringIdStringFromIndex(uint nIndex); 
    //��string_id_listָ���±��string_data_offָ���StringItem���ֶ�ֵ��
    //��Ϊָ���StringItem�ṹ���ļ�ƫ�Ƶ�ַ
    uint getStringIdsStringDataOffValueFromIndex(uint nIndex); 
    //��string_id_listָ���±��string_data_offָ���StringItem�ṹ���ļ�ƫ��
    BYTE *getStringIdsStringDataOffSTFromIndex(uint nIndex); 
    //��string_id_listָ���±��ַ����ĳ���
    DWORD getStringLenFromIndex(uint nIndex); 
    //��string_id_listָ���±��ַ������ļ�ƫ��
    DWORD getStringFillOffFromIndex(uint nIndex); 
    //�ռ��ַ�����
    bool ColletionStringIdItem();   

    //��ʼ��type_id_item��Ҫ�ṹ
    bool initTypeIdItemST();        
    //�ռ�type_id_item�����ַ�������
    bool ColletionTypeIdItem();     
    //��type_id_listָ���±���ַ���
    const char* getTypeIdStringFromIndex(uint nIndex);   
    //��ȡtype_id_item����
    DWORD getTypeItemSize();        

    //��ʼ��proto_id_item��Ҫ�ṹ
    bool initProtoIdItemST();        
    //�ռ�proto_id_item��
    bool ColletionProtoIdItem();     
	//��proto_id_listָ���±��proto_id_item�ṹ�׵�ַ
    STProtoIdItem* getProtoIdsSTFromIndex(uint nProtoIdsIndex); 
	//���proto_id_listָ���±�ĺ���ԭ����Ϣ(��Ϸ���ֵ�������б�)
    const char* getProtoIdsProtoStringFromIndex(uint nProtoIdsIndex);   
	//��ȡָ���±�parameters_offָ���TypeItemList{uint size; type_item list[size]}�ṹ�ļ�ƫ�Ƶ�ַ��
    //����ز���offΪ0�򷵻�ֵΪ��
    STTypeItemList *getProtoIdsTypeItemListSTFileOffsetFromIndex(uint nProtoIdsIndex);
	//��proto_id_item����ָ���±귽���ļ��򷵻�ֵ�������ַ���
    const char* getProtoIdsShortyIdxStringFromIndex(uint nProtoIdsIdex); 
    //��proto_id_itemָ���±귽���ķ��������ַ���
    const char* getProtoIdsReturnTypeIdxStringFromIndex(uint nProtoIdsIndex); 
    //��proto_id_itemָ���±귽���Ĳ����б��ַ���,����ֵ��Ҫ�ֹ��ͷ�    
    const char* getProtoIdsParametersStringFromIndex(uint nProtoIdsIndex); 
    //��ָ���±�proto_id_item�ṹ�е�ShortyIdx�ֶ�ֵ
    uint32_t getProtoIdsShortyIdxValueFromIndex(uint nProtoIdsIndex); 
    //��ָ���±�proto_id_item�ṹ�е�ReturnTypeIdx�ֶ�ֵ 
    uint16_t getProtoIdsReturnTypeIdxValueFromIndex(uint nProtoIdsIndex);         
    //��ȡָ���±귽���Ĳ����б��ֶ�ֵ
    uint32_t getProtoIdsParametersOffValueFromIndex(uint nProtoIdsIndex);
    //��ָ���±�proto_id_item�ṹ�е�Parameter�ֶ�ֵ
    //DWORD getProtoIdsParametersValueFromIndex(uint nProtoIdsIndex); 

    //��ʼ����ȡfield_id_item��Ҫ�ṹ
    bool initFieldIdItemST();        
    //�ռ�field_id_item��
    bool ColletionFieldIdItem();     
	//��field_id_listָ���±��field_id_item�ṹ�׵�ַ
    STFieldIdItem* getFieldIdSTFromIndex(uint nIndex);   
    //��FieldIds�ṹ����ָ���±��field_id_item�ṹ��class_idx_�ֶ�ֵ
    uint16_t getFieldIdsClassIdxValueFromIndex(uint nIndex);   
    //��FieldIds�ṹ����ָ���±��field_id_item�ṹ��proto_idx_�ֶ�ֵ
    uint16_t getFieldIdsTypeIdxValueFromIndex(uint nIndex);  
    //��FieldIds�ṹ����ָ���±��field_id_item�ṹ��name_idx_�ֶ�ֵ
    uint32_t getFieldIdsNameIdxValueFromIndex(uint nIndex);  
    //��ȡ��MapItem�ṹ����������FieldIdSize����
    DWORD getFieldIdSizeFromSave();    
    //����ͬ���ܵĺ�����
//     //��field_id_item����ָ���±��class_idx_�ֶ�ֵ
// 	DWORD getFieldClassIdxValueFromIndex(uint nIndex);
//     //��field_id_item����ָ���±��proto_idx_�ֶ�ֵ
// 	DWORD getFieldTypeIdxValueFromIndex(uint nIndex); 
//     //��field_id_item����ָ���±��name_idx_�ֶ�ֵ
// 	DWORD getFieldNameIdxValueFromIndex(uint nIndex); 
    //��field_id_item����ָ���±��type_idx_��ʾ���ַ���
	const char* getFieldTypeIdxStringFromIndex(uint nIndex); 
    //��field_id_item����ָ���±��class_idx_��ʾ���ַ���
	const char* getFieldClassIdxStringFromIndex(uint nIndex);
    //��field_id_item����ָ���±��name_idx_��ʾ���ַ���
	const char* getFieldNameIdxStringFromIndex(uint nIndex); 

    //��ʼ����ȡmethod_id_item��Ҫ�ṹ
    bool initMethodIdItemST();        
    //�ռ�method_id_item������
    bool ColletionMethodIdItem();     
    /*
		��method_id_list����ָ���±�Ľṹ�׵�ַ
		{ uint16_t class_idx_; 
          uint16_t proto_idx_;
          uint32_t name_idx_;}
	*/
    STMethodIdItem* getMethodIdSTFromIndex(uint nIndex);   
    //��ȡMethodIdsSize����
    DWORD getMethodIdsSizeFromSave();    
    //��ȡmethod_idsָ���±��ۺ��ַ�����Ϣ,����ֵ��Ҫ�ֶ�delete[]
    const char* getMethodIdsStringFromIndex(uint nIndex);
    //��ȡmethod_idsָ���±귵������,����ֵ��Ҫ�ֶ�delete[]
    const char* getMethodIdsRetStringFromIndex(uint nIndex);      
    //��ȡmethod_idsָ���±��������,����ֵ��Ҫ�ֶ�delete[]
    const char* getMethodIdsParemeterStringFromIndex(uint nIndex);   
    //��ʾָ�������±���ַ�������ʽΪ������.�����������Ѿ�����
    void showMethodStringAt(uint nIndex);               
    //��method_id_item����ָ���±귽�������ַ���
	const char* getMethodClassIdxStringFromIndex(uint nIndex); 
    //��method_id_item����ָ���±귽���ķ���ԭ���ַ���
	const char* getMethodProtoIdxStringFromIndex(uint nIndex);
    //��method_id_item����ָ���±귽���ķ������ַ���
	const char* getMethodNameIdxStringFromIndex(uint nIndex); 
    //��method_id_item����ָ���±��class_idx_�ֶ�ֵ������ʵ��Ϊ�ַ�����type_ids���±�
	uint16_t getMethodClassIdxValueFromIndex(uint nIndex); 
    //��method_id_item����ָ���±��proto_idx_�ֶ�ֵ����ʵ��Ϊ�ַ�����proto_ids���±�
	uint16_t getMethodProtoIdxValueFromIndex(uint nIndex);
    //��method_id_item����ָ���±��name_idx_�ֶ�ֵ����ʵ��Ϊ�ַ�����string_ids���±�
	uint32_t getMethodNameIdxValueFromIndex(uint nIndex); 

    //��ʼ��class_def_item��Ҫ�ṹ
    bool initClassDefItemST();        
    //�ռ�Class_Def_item��
    bool ColletionClassDefItem();     
    //������Ϣ�б�(Class_Def_list)ָ���±�Ľṹָ��
    PSTClassDefItem getClassDefSTFromId(uint nIndex);   
    //��ȡClassDefSize����
    DWORD getClassDefSizeFromSave();    
    //��ȡclass_def_item�±�ṹ�е�class_idx_�ֶ�ֵ
    uint16_t getClassClassIdxValueFromIndex(uint nIndex);        
    //��ȡclass_def_item�±�ṹ�е�pad1_�ֶ�ֵ	
    uint16_t getClassPad1ValueFromIndex(uint nIndex);				
    //��ȡclass_def_item�±�ṹ�е�access_flags_�ֶ�ֵ
    uint32_t getClassAccessFlagsValueFromIndex(uint nIndex);        
    //��ȡclass_def_item�±�ṹ�е�superclass_idx_�ֶ�ֵ
    uint16_t getClassSuperclassIdxValueFromIndex(uint nIndex);      
    //��ȡclass_def_item�±�ṹ�е�pad2_�ֶ�ֵ
    uint16_t getClassPad2ValueFromIndex(uint nIndex);				
    //��ȡclass_def_item�±�ṹ�е�interfaces_off�ֶ�ֵ
    uint32_t getClassInterfaceOffValueFromIndex(uint nIndex);        
    //��ȡclass_def_item�±�ṹ�е�source_file_idx_�ֶ�ֵ
    uint32_t getClassSourceFileIdxValueFromIndex(uint nIndex);        
    //��ȡclass_def_item�±�ṹ�е�annotations_off_�ֶ�ֵ
    uint32_t getClassAnnotationsOffValueFromIndex(uint nIndex);      
    //��ȡclass_def_item�±�ṹ�е�class_data_off_�ֶ�ֵ
    uint32_t getClassClassDataOffValueFromIndex(uint nIndex);        
    //��ȡclass_def_item�±�ṹ�е�static_values_off_�ֶ�ֵ
    uint32_t getClassStaticValuesOffValueFromIndex(uint nIndex);        
    
    //��ȡָ���±��ClassDef�ṹ�е�class_idx_�ֶ�ָ�����·���ַ���
	const char* getClassClassIdxStringFromIndex(uint nIndex);			
    //��ȡָ���±��ClassDef�ṹ�е�access_flags_�ֶ�ָ��ķ��ʱ�־�ַ���,
    //����ֵ��Ҫ�ֶ��������ͷ�
	const char* getClassAccessFlagsStringFromIndex(uint nIndex);		
    //��ȡָ���±��ClassDef�ṹ�е�superclass_idx_�ֶ�ָ��ĸ���·���ַ���
	const char* getClassSuperClassIdxStringFromIndex(uint nIndex);		
    //��ȡָ���±��ClassDef�ṹ�е�source_file_idx_�ֶ�ָ����ַ���
	const char* getClassSourceFileIdxStringFromIndex(uint nIndex);		
    //������ӦClass�ṹ�е�class_annotations_off_�ֶ�ֵ�ж��Ƿ���Ҫ��������Ϣ
    bool isClassNeedShowAnnotationsString(uint nIndex);
    //��ȡ��ӦClass�ṹ�е�class_annotations_off_�ṹ�����ַ���,����ֵ��Ҫ�ֶ��ͷ�
    const char* getClassAnnotationStringFromIndex(uint nIndex);
    //��ȡָ��class_def_item�ṹ�±��STAnnotationsDirectoryItem�ṹ�ļ�ƫ��ָ��
    PSTAnnotationsDirectoryItem getClassAnnotationsDirectoryItemSTFileOffsetFromIndex(uint nIndex);
    
    //��ȡ��ӦClass�ṹ�е�class_annotations_off_�ṹ��class_annotations_off_�ֶ�ֵ
    uint32_t getClassAnnotationsClassAnnotationsOffValueFromIndex(uint nIndex);
    //��ȡ��ӦClass�ṹ�е�class_annotations_off_�ṹ��fields_size_�ֶ�ֵ
    uint32_t getClassAnnotationsFieldsSizeValueFromIndex(uint nIndex);
    //��ȡ��ӦClass�ṹ�е�class_annotations_off_�ṹ��methods_size_�ֶ�ֵ
    uint32_t getClassAnnotationsMethodsSizeValueFromIndex(uint nIndex);
    //��ȡ��ӦClass�ṹ�е�class_annotations_off_�ṹ��parameters_size_�ֶ�ֵ
    uint32_t getClassAnnotationsParametersSizeValueFromIndex(uint nIndex);
    
    //������ӦClass�ṹ�е�interfaces_off_�ֶ�ֵ�ж��Ƿ���Ҫ��������Ϣ
    bool isClassNeedShowInterfacesString(uint nIndex);
    //��ȡ��ӦClass�ṹ�е�class_interfaces_off_�ṹ����,����ֵ��Ҫ�ֶ��ͷ�
    const char* getClassInterfacesStringFromIndex(uint nIndex);
    //��ȡָ��Class�±��interfaces_off_�ֶ�ָ���type_item_list�ṹ���ļ��е�ƫ��
    PSTTypeItemList getClassInterfaceListSTFileOffsetFromIndex(uint nIndex);   
    //��ȡָ��Class�±��interfaces_off_�ṹ�µ�list_�ṹ����
    uint32_t getClassInterfaceListSizeFromIndex(uint nIndex);

	//����class_def_item->class_data_off_�ֶ�ֵ�ж��Ƿ���Ҫ���
	bool isClassNeedShowClassDataString(uint nIndex);
    //��ȡ��ӦClass�ṹ�е�class_data_off_ָ���class_data_item�ṹ�ַ�������,
    //����ֵ��Ҫ�ֶ��ͷ�
    const char* getClassClassDataStringFromIndex(uint nIndex);
	//��ȡָ��class_def_item�ṹ�е�class_data_off�ֶ�ֵ����ΪSTClassDataItem�ṹ�ļ�ƫ��
	PSTClassDataItem getClassClassDataSTFileOffsetFromIndex(uint nIndex);
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
	//��ȡָ����ʼָ����LEB128���ݵ�BYTE��ַ��Ĭ��2��LEB128����Ϊ��
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
	BYTE* getClassInstanceFieldsSTAddrFromIndex(uint nIndex);
	
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
	//��ȡָ��class_def_item->class_data_off_->direct_methods_size��Ӧ�����ݵ�ַ,û���򷵻ؿ�ָ�룡����
    BYTE* getClassDirectMethodsSTAddrFromIndex(uint nIndex);
    //��ȡָ����DirectMethodָ������ݽṹ��method_idx����
    uint32_t getClassDirectMethodsBaseMethodIdxFromIndex(uint nIndex);
    //��ȡָ����DirectMethodָ������ݽṹ��idx���ܶ�
    uint32_t getClassDirectMethodsMethodIdxSubFromIndex(uint nIndex, uint nMethodIndex);
    //��ȡָ��class_def_item->class_data_off_->direct_methods_size->data_off_�Ƿ���Ҫ���
    bool isClassDirectMethodsNeedShowDataOffStringFromIndex(uint nIndex);
    //��ȡָ��class_def_item->class_data_off_->direct_methods_size->data_off_ָ��ṹ������
    const char* getClassDirectMethodsDataOffStringFromIndex(DWORD dwOff);
    //��ȡָ�����±�ָ��DirectMethod��ָ��ṹ������
    const char* getClassDirectMethodsDataOffStringFromIndex(uint nClassIndex, uint nDirectMethodIndex);
    //��ȡָ��class_def_item->class_data_off_->direct_methods_size->data_off_ָ��ṹ�׵�ַ
    PSTCodeItem getClassDirectMethodsDataOffSTFromeIndex(uint nIndex);
    //��ȡdwOffָ��code_item�ṹ��register_size_�ֶ�ֵ
    uint16_t getClassDirectMethodsDataOffRegisterSizeValueFromIndex(DWORD dwOff);
    //��ȡdwOffָ��code_item�ṹ��ins_size_�ֶ�ֵ
    uint16_t getClassDirectMethodsDataOffInsSizeValueFromIndex(DWORD dwOff);
    //��ȡdwOffָ��code_item�ṹ��out_size_�ֶ�ֵ
    uint16_t getClassDirectMethodsDataOffOutsSizeValueFromIndex(DWORD dwOff);
    //��ȡdwOffָ��code_item�ṹ��tries_size_�ֶ�ֵ
    uint16_t getClassDirectMethodsDataOffTriesSizeValueFromIndex(DWORD dwOff);
    //��ȡdwOffָ��code_item�ṹ��debug_info_off_�ֶ�ֵ
    uint32_t getClassDirectMethodsDataOffDebugInfoOffValueFromIndex(DWORD dwOff);
    //��ȡdwOffָ��code_item�ṹ�µ�insns���ݴ�С��ʵ����WORD�ĸ���
    uint32_t getClassDirectMethodsDataOffInsnsSizeInCodeUnitsValueFromIndex(DWORD dwOff);
    //��ȡdwOffָ��code_item�ṹ�µ�insns����(������)��ʼ��ַ
    WORD* getClassDirectMethodsDataOffInsnsFileOffsetFromIndex(DWORD dwOff);
    //��ȡClassDirectMethodsDataOffInsns�µĻ����룬����ֵ�ֶ��ͷ�
    const char* getClassDirectMethodsDataOffInsnsMachineCode(PSTCodeItem pSTCIFileOffset);
    //��ȡָ����ָ��directmethod�Ļ����룬����ֵ�ֶ��ͷ�
    const char* getClassDirectMethodsDataOffInsnsMachineCode(uint nClassIndex, uint nDirectMethodIndex);
	
	//ָ��class_def_item->class_data_off_->virtual_methods_size�ֶ�ֵ�Ƿ�Ϊ0
	bool isClassNeedShowVirtualMethodsStringFromIndex(uint nIndex);
	//��ȡָ��class_def_item->class_data_off_->virtual_methods_size�ֶ�
    //ָ��Ľṹ�ַ�����Ϣ,����ֵ��Ҫ�ֶ��ͷ�
	const char* getClassVirtualMethodsSTStringFromIndex(uint nIndex, uint nVirtualMethodIndex);
	//��ȡ��pByteΪ��ַ��method_item�ṹ��field_idx_diff�ֶ�ֵ
	DWORD getClassVirtualMethodsFieldIdxDiffValueIndex(BYTE *pByte);
	//��ȡ��pByteΪ��ַ��method_item�ṹ��access_flags�ֶ�ֵ
	DWORD getClassVirtualMethodsAccessFlagsValueIndex(BYTE *pByte);
	//��ȡ��pByteΪ��ַ��method_item�ṹ��code_off�ֶ�ֵ
    DWORD getClassVirtualMethodsCodeOffValueIndex(BYTE *pByte);
    //��ȡָ��class_def_item[nIndex]->class_data_off_->
    //            virtual_methods_size[nVirtualIndex]->code_off�ֶ�ֵ,
	DWORD getClassVirtualMethodsCodeOffValueFromIndex(uint nIndex, uint nItemIndex);
	//��ȡָ��class_def_item->class_data_off_->virtual_methods_sizeָ��������׵�ַ,û���򷵻ؿ�ָ�룡����
    BYTE* getClassVirtualMethodsSTAddrFromIndex(uint nIndex);
    //��ȡָ����VirtualMethodָ������ݽṹ��method_idx����
    uint32_t getClassVirtualMethodsBaseMethodIdxFromIndex(uint nIndex);
    //��ȡָ����VirtualMethodָ������ݽṹ��idx���ܶ�
    uint32_t getClassVirtualMethodsMethodIdxSubFromIndex(uint nIndex, uint nMethodIndex);
    //��ȡָ��class_def_item->class_data_off_->virtual_methods_size->data_off_�Ƿ���Ҫ���
    bool isClassVirturlMethodsNeedShowDataOffStringFromIndex(uint nIndex);
    //��ȡָ��data_off_�ֶ�ָ��ķ�����Ϣ�ַ���������ֵ��Ҫ�ֶ��ͷ�delete[]   
    const char* getClassVirtualMethodsDataOffStringFromIndex(DWORD dwOff);
    //��ȡָ��class_def_itemָ��virtual_methods�µ�data_off_�ֶ�ָ��ķ�����Ϣ�ַ���������ֵ��Ҫ�ֶ��ͷ�delete[]   
    const char* getClassVirtualMethodsDataOffStringFromIndex(uint nIndex, uint nVirtualMethodIndex);
    //��ȡָ��class_def_item->class_data_off_->
    //            virtual_methods_size->data_off_ָ��Ľṹ���ļ�ƫ���׵�ַ
    PSTCodeItem getClassVirtualMethodsDataOffSTFileOffsetFromeIndex(uint nIndex);
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