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

    //初始化StringItem相关数据
    bool initStringItemInfo();  
    //获取MapItem结构中StringItem个数
    DWORD getStringItemSize();  
    //拿string_id_list指定下标的字符串
    const char* getStringIdStringFromIndex(uint nIndex); 
    //拿string_id_list指定下标的string_data_off指向的StringItem的字段值，
    //其为指向的StringItem结构的文件偏移地址
    uint getStringIdsStringDataOffValueFromIndex(uint nIndex); 
    //拿string_id_list指定下标的string_data_off指向的StringItem结构的文件偏移
    BYTE *getStringIdsStringDataOffSTFromIndex(uint nIndex); 
    //拿string_id_list指定下标字符串的长度
    DWORD getStringLenFromIndex(uint nIndex); 
    //拿string_id_list指定下标字符串的文件偏移
    DWORD getStringFillOffFromIndex(uint nIndex); 
    //收集字符串表
    bool ColletionStringIdItem();   

    //初始化type_id_item必要结构
    bool initTypeIdItemST();        
    //收集type_id_item所有字符串数据
    bool ColletionTypeIdItem();     
    //拿type_id_list指定下标的字符串
    const char* getTypeIdStringFromIndex(uint nIndex);   
    //获取type_id_item数量
    DWORD getTypeItemSize();        

    //初始化proto_id_item必要结构
    bool initProtoIdItemST();        
    //收集proto_id_item表
    bool ColletionProtoIdItem();     
	//拿proto_id_list指定下标的proto_id_item结构首地址
    STProtoIdItem* getProtoIdsSTFromIndex(uint nProtoIdsIndex); 
	//组合proto_id_list指定下标的函数原型信息(组合返回值及参数列表)
    const char* getProtoIdsProtoStringFromIndex(uint nProtoIdsIndex);   
	//获取指定下标parameters_off指向的TypeItemList{uint size; type_item list[size]}结构文件偏移地址，
    //若相关参数off为0则返回值为空
    STTypeItemList *getProtoIdsTypeItemListSTFileOffsetFromIndex(uint nProtoIdsIndex);
	//拿proto_id_item数组指定下标方法的极简返回值跟参数字符串
    const char* getProtoIdsShortyIdxStringFromIndex(uint nProtoIdsIdex); 
    //拿proto_id_item指定下标方法的返回类型字符串
    const char* getProtoIdsReturnTypeIdxStringFromIndex(uint nProtoIdsIndex); 
    //拿proto_id_item指定下标方法的参数列表字符串,返回值需要手工释放    
    const char* getProtoIdsParametersStringFromIndex(uint nProtoIdsIndex); 
    //拿指定下标proto_id_item结构中的ShortyIdx字段值
    uint32_t getProtoIdsShortyIdxValueFromIndex(uint nProtoIdsIndex); 
    //拿指定下标proto_id_item结构中的ReturnTypeIdx字段值 
    uint16_t getProtoIdsReturnTypeIdxValueFromIndex(uint nProtoIdsIndex);         
    //获取指定下标方法的参数列表字段值
    uint32_t getProtoIdsParametersOffValueFromIndex(uint nProtoIdsIndex);
    //拿指定下标proto_id_item结构中的Parameter字段值
    //DWORD getProtoIdsParametersValueFromIndex(uint nProtoIdsIndex); 

    //初始化读取field_id_item必要结构
    bool initFieldIdItemST();        
    //收集field_id_item表
    bool ColletionFieldIdItem();     
	//拿field_id_list指定下标的field_id_item结构首地址
    STFieldIdItem* getFieldIdSTFromIndex(uint nIndex);   
    //从FieldIds结构中拿指定下标的field_id_item结构的class_idx_字段值
    uint16_t getFieldIdsClassIdxValueFromIndex(uint nIndex);   
    //从FieldIds结构中拿指定下标的field_id_item结构的proto_idx_字段值
    uint16_t getFieldIdsTypeIdxValueFromIndex(uint nIndex);  
    //从FieldIds结构中拿指定下标的field_id_item结构的name_idx_字段值
    uint32_t getFieldIdsNameIdxValueFromIndex(uint nIndex);  
    //获取从MapItem结构解析出来的FieldIdSize个数
    DWORD getFieldIdSizeFromSave();    
    //有相同功能的函数了
//     //拿field_id_item数组指定下标的class_idx_字段值
// 	DWORD getFieldClassIdxValueFromIndex(uint nIndex);
//     //拿field_id_item数组指定下标的proto_idx_字段值
// 	DWORD getFieldTypeIdxValueFromIndex(uint nIndex); 
//     //拿field_id_item数组指定下标的name_idx_字段值
// 	DWORD getFieldNameIdxValueFromIndex(uint nIndex); 
    //拿field_id_item数组指定下标的type_idx_表示的字符串
	const char* getFieldTypeIdxStringFromIndex(uint nIndex); 
    //拿field_id_item数组指定下标的class_idx_表示的字符串
	const char* getFieldClassIdxStringFromIndex(uint nIndex);
    //拿field_id_item数组指定下标的name_idx_表示的字符串
	const char* getFieldNameIdxStringFromIndex(uint nIndex); 

    //初始化读取method_id_item必要结构
    bool initMethodIdItemST();        
    //收集method_id_item表数据
    bool ColletionMethodIdItem();     
    /*
		拿method_id_list数组指定下标的结构首地址
		{ uint16_t class_idx_; 
          uint16_t proto_idx_;
          uint32_t name_idx_;}
	*/
    STMethodIdItem* getMethodIdSTFromIndex(uint nIndex);   
    //获取MethodIdsSize个数
    DWORD getMethodIdsSizeFromSave();    
    //获取method_ids指定下标综合字符串信息,返回值需要手动delete[]
    const char* getMethodIdsStringFromIndex(uint nIndex);
    //获取method_ids指定下标返回类型,返回值需要手动delete[]
    const char* getMethodIdsRetStringFromIndex(uint nIndex);      
    //获取method_ids指定下标参数类型,返回值需要手动delete[]
    const char* getMethodIdsParemeterStringFromIndex(uint nIndex);   
    //显示指定方法下标的字符串，形式为“类名.方法名”，已经弃用
    void showMethodStringAt(uint nIndex);               
    //拿method_id_item数组指定下标方法的类字符串
	const char* getMethodClassIdxStringFromIndex(uint nIndex); 
    //拿method_id_item数组指定下标方法的方法原型字符串
	const char* getMethodProtoIdxStringFromIndex(uint nIndex);
    //拿method_id_item数组指定下标方法的方法名字符串
	const char* getMethodNameIdxStringFromIndex(uint nIndex); 
    //拿method_id_item数组指定下标的class_idx_字段值，，其实际为字符串在type_ids的下标
	uint16_t getMethodClassIdxValueFromIndex(uint nIndex); 
    //拿method_id_item数组指定下标的proto_idx_字段值，其实际为字符串在proto_ids的下标
	uint16_t getMethodProtoIdxValueFromIndex(uint nIndex);
    //拿method_id_item数组指定下标的name_idx_字段值，其实际为字符串在string_ids的下标
	uint32_t getMethodNameIdxValueFromIndex(uint nIndex); 

    //初始化class_def_item必要结构
    bool initClassDefItemST();        
    //收集Class_Def_item表
    bool ColletionClassDefItem();     
    //拿类信息列表(Class_Def_list)指定下标的结构指针
    PSTClassDefItem getClassDefSTFromId(uint nIndex);   
    //获取ClassDefSize个数
    DWORD getClassDefSizeFromSave();    
    //获取class_def_item下标结构中的class_idx_字段值
    uint16_t getClassClassIdxValueFromIndex(uint nIndex);        
    //获取class_def_item下标结构中的pad1_字段值	
    uint16_t getClassPad1ValueFromIndex(uint nIndex);				
    //获取class_def_item下标结构中的access_flags_字段值
    uint32_t getClassAccessFlagsValueFromIndex(uint nIndex);        
    //获取class_def_item下标结构中的superclass_idx_字段值
    uint16_t getClassSuperclassIdxValueFromIndex(uint nIndex);      
    //获取class_def_item下标结构中的pad2_字段值
    uint16_t getClassPad2ValueFromIndex(uint nIndex);				
    //获取class_def_item下标结构中的interfaces_off字段值
    uint32_t getClassInterfaceOffValueFromIndex(uint nIndex);        
    //获取class_def_item下标结构中的source_file_idx_字段值
    uint32_t getClassSourceFileIdxValueFromIndex(uint nIndex);        
    //获取class_def_item下标结构中的annotations_off_字段值
    uint32_t getClassAnnotationsOffValueFromIndex(uint nIndex);      
    //获取class_def_item下标结构中的class_data_off_字段值
    uint32_t getClassClassDataOffValueFromIndex(uint nIndex);        
    //获取class_def_item下标结构中的static_values_off_字段值
    uint32_t getClassStaticValuesOffValueFromIndex(uint nIndex);        
    
    //获取指定下标的ClassDef结构中的class_idx_字段指向的类路径字符串
	const char* getClassClassIdxStringFromIndex(uint nIndex);			
    //获取指定下标的ClassDef结构中的access_flags_字段指向的访问标志字符串,
    //返回值需要手动做数组释放
	const char* getClassAccessFlagsStringFromIndex(uint nIndex);		
    //获取指定下标的ClassDef结构中的superclass_idx_字段指向的父类路径字符串
	const char* getClassSuperClassIdxStringFromIndex(uint nIndex);		
    //获取指定下标的ClassDef结构中的source_file_idx_字段指向的字符串
	const char* getClassSourceFileIdxStringFromIndex(uint nIndex);		
    //根据相应Class结构中的class_annotations_off_字段值判断是否需要输出相关信息
    bool isClassNeedShowAnnotationsString(uint nIndex);
    //获取相应Class结构中的class_annotations_off_结构数据字符串,返回值需要手动释放
    const char* getClassAnnotationStringFromIndex(uint nIndex);
    //获取指定class_def_item结构下标的STAnnotationsDirectoryItem结构文件偏移指针
    PSTAnnotationsDirectoryItem getClassAnnotationsDirectoryItemSTFileOffsetFromIndex(uint nIndex);
    
    //获取相应Class结构中的class_annotations_off_结构中class_annotations_off_字段值
    uint32_t getClassAnnotationsClassAnnotationsOffValueFromIndex(uint nIndex);
    //获取相应Class结构中的class_annotations_off_结构中fields_size_字段值
    uint32_t getClassAnnotationsFieldsSizeValueFromIndex(uint nIndex);
    //获取相应Class结构中的class_annotations_off_结构中methods_size_字段值
    uint32_t getClassAnnotationsMethodsSizeValueFromIndex(uint nIndex);
    //获取相应Class结构中的class_annotations_off_结构中parameters_size_字段值
    uint32_t getClassAnnotationsParametersSizeValueFromIndex(uint nIndex);
    
    //根据相应Class结构中的interfaces_off_字段值判断是否需要输出相关信息
    bool isClassNeedShowInterfacesString(uint nIndex);
    //获取相应Class结构中的class_interfaces_off_结构数据,返回值需要手动释放
    const char* getClassInterfacesStringFromIndex(uint nIndex);
    //获取指定Class下标的interfaces_off_字段指向的type_item_list结构在文件中的偏移
    PSTTypeItemList getClassInterfaceListSTFileOffsetFromIndex(uint nIndex);   
    //获取指定Class下标的interfaces_off_结构下的list_结构数量
    uint32_t getClassInterfaceListSizeFromIndex(uint nIndex);

	//根据class_def_item->class_data_off_字段值判断是否需要输出
	bool isClassNeedShowClassDataString(uint nIndex);
    //获取相应Class结构中的class_data_off_指向的class_data_item结构字符串数据,
    //返回值需要手动释放
    const char* getClassClassDataStringFromIndex(uint nIndex);
	//获取指定class_def_item结构中的class_data_off字段值，其为STClassDataItem结构文件偏移
	PSTClassDataItem getClassClassDataSTFileOffsetFromIndex(uint nIndex);
	//获取指定class_def_item->class_data_off_->static_fields_size字段值，这是LEB128类型数据
	uint32_t getClassClassDataStaticFieldsSizeValueFromIndex(uint nIndex);
	//获取指定class_def_item->class_data_off_->instance_fields_size字段值，这是LEB128类型数据
	uint32_t getClassClassDataInstanceFieldsSizeValueFromIndex(uint nIndex);
	//获取指定class_def_item->class_data_off_->direct_methods_size字段值，这是LEB128类型数据
	uint32_t getClassClassDataDirectMethodsSizeValueFromIndex(uint nIndex);
	//获取指定class_def_item->class_data_off_->virtual_methods_size字段值，
	//这是LEB128类型数据表示这个类含有的virtual_method数量
	uint32_t getClassClassDataVirtualMethodsSizeValueFromIndex(uint nIndex);
	//获取指定class_def_item->class_data_off_->virtual_methods_size字段实际占用的字节长度
	uint32_t getClassClassDataStaticFieldsSizeLenFromIndex(uint nIndex);
	//获取指定class_def_item->class_data_off_->instance_fields_size字段实际占用的字节长度
	uint32_t getClassClassDataInstanceFieldsSizeLenFromIndex(uint nIndex);
	//获取指定class_def_item->class_data_off_->direct_methods_size字段实际占用的字节长度
	uint32_t getClassClassDataDirectMethodsSizeLenFromIndex(uint nIndex);
	//获取指定class_def_item->class_data_off_->virtual_methods_size字段实际占用的字节长度
	uint32_t getClassClassDataVirtualMethodsSizeLenFromIndex(uint nIndex);

	//获取class_def_item->class_data_off_各字段数量指定后的首地址，其依次为实际数据的属性
	BYTE *getClassClassDataAttributeAddrFromIndex(uint nIndex);

	//指定class_def_item->class_data_off_->static_fields_size字段值是否为0
	bool isClassNeedShowStaticFieldsStringFromIndex(uint nIndex);
	//获取指定class_def_item->class_data_off_->static_fields_size字段的字符串,返回值需要手动释放
	const char* getClassStaticFieldsStringFromIndex(uint nIndex, uint nFieldIndex);
	//获取指定class_def_item->class_data_off_->static_fields->field_idx_diff字段值,这是一个LEB128数据
	DWORD getClassStaticFieldsFieldIdxDiffValueIndex(BYTE *pByte);
	//获取指定class_def_item->class_data_off_->static_fields->access_flags字段值,这是一个LEB128数据
	DWORD getClassStaticFieldsAccessFlagsValueIndex(BYTE *pByte);
	//获取指针起始指定个LEB128数据的BYTE地址，默认2个LEB128数据为界
	BYTE* getNextSTAddr(BYTE *pByte, int nLeb128Count = 2);
	
	//指定class_def_item->class_data_off_->instance_fields_size字段值是否为0
	bool isClassNeedShowInstanceFieldsStringFromIndex(uint nIndex);
	//获取指定class_def_item->class_data_off_->instance_fields_size字段的字符串,返回值需要手动释放
	const char* getClassInstanceFieldsStringFromIndex(uint nIndex, uint nFieldIndex);
	//获取指定class_def_item->class_data_off_->instance_fields_size->field_idx_diff字段值,这是一个LEB128数据
	DWORD getClassInstanceFieldsFieldIdxDiffValueIndex(BYTE *pByte);
	//获取指定class_def_item->class_data_off_->instance_fields_size->access_flags字段值,这是一个LEB128数据
	DWORD getClassInstanceFieldsAccessFlagsValueIndex(BYTE *pByte);
	//获取指定class_def_item->class_data_off_->instance_fields指向的数据地址,没有则返回空指针！！！
	BYTE* getClassInstanceFieldsSTAddrFromIndex(uint nIndex);
	
	//指定class_def_item->class_data_off_->direct_methods_size字段值是否为0
	bool isClassNeedShowDirectMethodsStringFromIndex(uint nIndex);
	//获取指定class_def_item->class_data_off_->direct_methods_size字段的字符串,返回值需要手动释放
	const char* getClassDirectMethodsStringFromIndex(uint nIndex, uint nFieldIndex);
	//获取指定class_def_item->class_data_off_->direct_methods_size->field_idx_diff字段值,这是一个LEB128数据
	DWORD getClassDirectMethodsMethodIdxDiffValueIndex(BYTE *pByte);
	//获取指定class_def_item->class_data_off_->direct_methods_size->access_flags字段值,这是一个LEB128数据
	DWORD getClassDirectMethodsAccessFlagsValueIndex(BYTE *pByte);
	//获取指定class_def_item->class_data_off_->direct_methods_size->code_off字段值,这是一个LEB128数据
    DWORD getClassDirectMethodsCodeOffValueIndex(BYTE *pByte);
    //获取指定class_def_item->class_data_off_->virtual_methods_size->code_off字段值,这是一个LEB128数据
	DWORD getClassDirectMethodsCodeOffValueIndex(uint nIndex, uint nItemIndex);
	//获取指定class_def_item->class_data_off_->direct_methods_size对应的数据地址,没有则返回空指针！！！
    BYTE* getClassDirectMethodsSTAddrFromIndex(uint nIndex);
    //获取指定类DirectMethod指向的数据结构的method_idx基数
    uint32_t getClassDirectMethodsBaseMethodIdxFromIndex(uint nIndex);
    //获取指定类DirectMethod指向的数据结构的idx差总额
    uint32_t getClassDirectMethodsMethodIdxSubFromIndex(uint nIndex, uint nMethodIndex);
    //获取指定class_def_item->class_data_off_->direct_methods_size->data_off_是否需要输出
    bool isClassDirectMethodsNeedShowDataOffStringFromIndex(uint nIndex);
    //获取指定class_def_item->class_data_off_->direct_methods_size->data_off_指向结构体数据
    const char* getClassDirectMethodsDataOffStringFromIndex(DWORD dwOff);
    //获取指定类下标指定DirectMethod的指向结构体数据
    const char* getClassDirectMethodsDataOffStringFromIndex(uint nClassIndex, uint nDirectMethodIndex);
    //获取指定class_def_item->class_data_off_->direct_methods_size->data_off_指向结构首地址
    PSTCodeItem getClassDirectMethodsDataOffSTFromeIndex(uint nIndex);
    //获取dwOff指向code_item结构的register_size_字段值
    uint16_t getClassDirectMethodsDataOffRegisterSizeValueFromIndex(DWORD dwOff);
    //获取dwOff指向code_item结构的ins_size_字段值
    uint16_t getClassDirectMethodsDataOffInsSizeValueFromIndex(DWORD dwOff);
    //获取dwOff指向code_item结构的out_size_字段值
    uint16_t getClassDirectMethodsDataOffOutsSizeValueFromIndex(DWORD dwOff);
    //获取dwOff指向code_item结构的tries_size_字段值
    uint16_t getClassDirectMethodsDataOffTriesSizeValueFromIndex(DWORD dwOff);
    //获取dwOff指向code_item结构的debug_info_off_字段值
    uint32_t getClassDirectMethodsDataOffDebugInfoOffValueFromIndex(DWORD dwOff);
    //获取dwOff指向code_item结构下的insns数据大小，实际是WORD的个数
    uint32_t getClassDirectMethodsDataOffInsnsSizeInCodeUnitsValueFromIndex(DWORD dwOff);
    //获取dwOff指向code_item结构下的insns数据(机器码)起始地址
    WORD* getClassDirectMethodsDataOffInsnsFileOffsetFromIndex(DWORD dwOff);
    //获取ClassDirectMethodsDataOffInsns下的机器码，返回值手动释放
    const char* getClassDirectMethodsDataOffInsnsMachineCode(PSTCodeItem pSTCIFileOffset);
    //获取指定类指定directmethod的机器码，返回值手动释放
    const char* getClassDirectMethodsDataOffInsnsMachineCode(uint nClassIndex, uint nDirectMethodIndex);
	
	//指定class_def_item->class_data_off_->virtual_methods_size字段值是否为0
	bool isClassNeedShowVirtualMethodsStringFromIndex(uint nIndex);
	//获取指定class_def_item->class_data_off_->virtual_methods_size字段
    //指向的结构字符串信息,返回值需要手动释放
	const char* getClassVirtualMethodsSTStringFromIndex(uint nIndex, uint nVirtualMethodIndex);
	//获取以pByte为地址的method_item结构的field_idx_diff字段值
	DWORD getClassVirtualMethodsFieldIdxDiffValueIndex(BYTE *pByte);
	//获取以pByte为地址的method_item结构的access_flags字段值
	DWORD getClassVirtualMethodsAccessFlagsValueIndex(BYTE *pByte);
	//获取以pByte为地址的method_item结构的code_off字段值
    DWORD getClassVirtualMethodsCodeOffValueIndex(BYTE *pByte);
    //获取指定class_def_item[nIndex]->class_data_off_->
    //            virtual_methods_size[nVirtualIndex]->code_off字段值,
	DWORD getClassVirtualMethodsCodeOffValueFromIndex(uint nIndex, uint nItemIndex);
	//获取指定class_def_item->class_data_off_->virtual_methods_size指向的数据首地址,没有则返回空指针！！！
    BYTE* getClassVirtualMethodsSTAddrFromIndex(uint nIndex);
    //获取指定类VirtualMethod指向的数据结构的method_idx基数
    uint32_t getClassVirtualMethodsBaseMethodIdxFromIndex(uint nIndex);
    //获取指定类VirtualMethod指向的数据结构的idx差总额
    uint32_t getClassVirtualMethodsMethodIdxSubFromIndex(uint nIndex, uint nMethodIndex);
    //获取指定class_def_item->class_data_off_->virtual_methods_size->data_off_是否需要输出
    bool isClassVirturlMethodsNeedShowDataOffStringFromIndex(uint nIndex);
    //获取指定data_off_字段指向的方法信息字符串，返回值需要手动释放delete[]   
    const char* getClassVirtualMethodsDataOffStringFromIndex(DWORD dwOff);
    //获取指定class_def_item指定virtual_methods下的data_off_字段指向的方法信息字符串，返回值需要手动释放delete[]   
    const char* getClassVirtualMethodsDataOffStringFromIndex(uint nIndex, uint nVirtualMethodIndex);
    //获取指定class_def_item->class_data_off_->
    //            virtual_methods_size->data_off_指向的结构于文件偏移首地址
    PSTCodeItem getClassVirtualMethodsDataOffSTFileOffsetFromeIndex(uint nIndex);
    //获取data_off_结构下的register_size_字段值
    uint16_t getClassVirtualMethodsDataOffRegisterSizeValueFromIndex(DWORD dwOff);
    //获取data_off_结构下的ins_size_字段值
    uint16_t getClassVirtualMethodsDataOffInsSizeValueFromIndex(DWORD dwOff);
    //获取data_off_结构下的out_size_字段值
    uint16_t getClassVirtualMethodsDataOffOutsSizeValueFromIndex(DWORD dwOff);
    //获取data_off_结构下的tries_size_字段值
    uint16_t getClassVirtualMethodsDataOffTriesSizeValueFromIndex(DWORD dwOff);
    //获取data_off_结构下的debug_info_off_字段值
    uint32_t getClassVirtualMethodsDataOffDebugInfoOffValueFromIndex(DWORD dwOff);
    //获取data_off_结构下的insns数据大小，实际是WORD的个数
    uint32_t getClassVirtualMethodsDataOffInsnsSizeInCodeUnitsValueFromIndex(DWORD dwOff);
    //获取data_off_结构下的insns数据文件偏移起始地址
    WORD* getClassVirtualMethodsDataOffInsnsFileOffsetFromIndex(DWORD dwOff);
    //获取ClassVirtualMethodsDataOffInsns下的机器码，返回值手动释放
    const char* getClassVirtualMethodsDataOffInsnsMachineCode(PSTCodeItem pSTCI);


	//返回访问标志字符串，返回值需要手动delete []
	const char* getClassAccessFlagsString(DWORD dwFlags);
	
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