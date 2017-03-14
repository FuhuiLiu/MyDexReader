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
    const char* getShortyIdxStringFromIndex(uint nIdex); //拿proto_id_item数组指定下标方法的极简返回值跟参数字符串
    const char* getReturnTypeIdxStringFromIndex(uint nIndex); //拿proto_id_item指定下标方法的返回类型字符串
    const char* getParametersStringFromIndex(uint nIndex); //拿proto_id_item指定下标方法的参数列表字符串,返回值需要手工释放    
    DWORD getShortyIdxValueFromIndex(uint nIdex); //拿指定下标方法的ShortyIdx字段值
    DWORD getReturnTypeIdxValueFromIndex(uint nIndex); //拿指定下标方法的ReturnTypeIdx字段值 
    DWORD getParametersValueFromIndex(uint nIndex); //拿指定下标方法的Parameter字段值

    bool initFieldIdItemST();        //初始化field_id_item必要结构
    bool ColletionFieldIdItem();     //收集field_id_item表
    STFieldIdItem* getFieldIdSTFromId(uint nIndex);   //拿field_id_list指定下标的结构首地址
    uint16_t getClassIdxValueFromId(uint nIndex);   //从MethodId结构中拿class_idx_字段值
    uint16_t getProtoIdxValueFromId(uint nIndex);   //从MethodId结构中拿proto_idx_字段值
    uint32_t getNameIdxValueFromId(uint nIndex);   //从MethodId结构中拿name_idx_字段值
    DWORD getFieldIdSizeFromSave();    //获取FieldIdSize个数
	DWORD getFieldClassIdxValueFromIndex(uint nIndex); //拿field_id_item数组指定下标的class_idx_字段值
	DWORD getFieldTypeIdxValueFromIndex(uint nIndex); //拿field_id_item数组指定下标的proto_idx_字段值
	DWORD getFieldNameIdxValueFromIndex(uint nIndex); //拿field_id_item数组指定下标的name_idx_字段值
	const char* getFieldTypeIdxStringFromId(uint nIndex); //拿field_id_item数组指定下标的type_idx_表示的字符串
	const char* getFieldClassIdxStringFromId(uint nIndex); //拿field_id_item数组指定下标的class_idx_表示的字符串
	const char* getFieldNameIdxStringFromId(uint nIndex); //拿field_id_item数组指定下标的name_idx_表示的字符串

    bool initMethodIdItemST();        //初始化method_id_item必要结构
    bool ColletionMethodIdItem();     //收集method_id_item表
    STMethodIdItem* getMethodIdSTFromId(uint nIndex);   //拿method_id_list指定下标的结构首地址
    DWORD getMethodIdSizeFromSave();    //获取MethodIdSize个数
    void showMethodStringAt(uint nIndex);               //显示方法字符串
	const char* getMethodClassIdxStringFromIndex(uint nIndex); //拿method_id_item数组指定下标方法的类字符串
	const char* getMethodProtoIdxStringFromIndex(uint nIndex); //拿method_id_item数组指定下标方法的方法原型字符串
	const char* getMethodNameIdxStringFromIndex(uint nIndex); //拿method_id_item数组指定下标方法的方法名字符串
	uint16_t getMethodClassIdxValueFromIndex(uint nIndex); //拿method_id_item数组指定下标的class_idx_字段值
	uint16_t getMethodProtoIdxValueFromIndex(uint nIndex); //拿method_id_item数组指定下标的proto_idx_字段值
	uint32_t getMethodNameIdxValueFromIndex(uint nIndex); //拿method_id_item数组指定下标的name_idx_字段值

    bool initClassDefItemST();        //初始化classdef_item必要结构
    bool ColletionClassDefItem();     //收集ClassDef_item表
    STClassDefItem* getClassDefSTFromId(uint nIndex);   //拿ClassDef_list指定下标的结构首地址
    DWORD getClassDefSizeFromSave();    //获取ClassDefSize个数
    uint16_t getClassClassIdxValueFromIndex(uint nIndex);        //获取class_def_item下标结构中的class_idx_字段值
    uint16_t getClassPad1ValueFromIndex(uint nIndex);				//获取class_def_item下标结构中的pad1_字段值	
    uint32_t getClassAccessFlagsValueFromIndex(uint nIndex);        //获取class_def_item下标结构中的access_flags_字段值
    uint16_t getClassSuperclassIdxValueFromIndex(uint nIndex);        //获取class_def_item下标结构中的superclass_idx_字段值
    uint16_t getClassPad2ValueFromIndex(uint nIndex);				//获取class_def_item下标结构中的pad2_字段值
    uint32_t getClassInterfaceOffValueFromIndex(uint nIndex);        //获取class_def_item下标结构中的interfaces_off字段值
    uint32_t getClassSourceFileIdxValueFromIndex(uint nIndex);        //获取class_def_item下标结构中的source_file_idx_字段值
    uint32_t getClassAnnotationsOffValueFromIndex(uint nIndex);        //获取class_def_item下标结构中的annotations_off_字段值
    uint32_t getClassClassDataOffValueFromIndex(uint nIndex);        //获取class_def_item下标结构中的class_data_off_字段值
    uint32_t getClassStaticValuesOffValueFromIndex(uint nIndex);        //获取class_def_item下标结构中的static_values_off_字段值

	const char* getClassClassIdxStringFromIndex(uint nIndex);			//获取指定下标的ClassDef结构中的class_idx_的字符串
	const char* getClassAccessFlagsStringFromIndex(uint nIndex);		//获取指定下标的ClassDef结构中的access_flags_的字符串,返回值需要手动做数组释放
	const char* getClassSuperClassIdxStringFromIndex(uint nIndex);		//获取指定下标的ClassDef结构中的superclass_idx_的字符串
	const char* getClassSourceFileIdxStringFromIndex(uint nIndex);		//获取指定下标的ClassDef结构中的source_file_idx_的字符串
    //根据相应Class结构中的class_annotations_off_判断是否需要输出相关信息
    bool isClassNeedShowAnnotationsString(uint nIndex);
    //获取相应Class结构中的class_annotations_off_结构数据,返回值需要手动释放
    const char* getClassAnnotationStringFromIndex(uint nIndex);
    //获取指定下标的STAnnotationsDirectoryItem结构指针
    PSTAnnotationsDirectoryItem getClassAnnotationsDirectoryItemSTFromIndex(uint nIndex);
    
    //获取相应Class结构中的class_annotations_off_结构中class_annotations_off_字段值
    uint32_t getClassAnnotationsClassAnnotationsOffValueFromIndex(uint nIndex);
    //获取相应Class结构中的class_annotations_off_结构中fields_size_字段值
    uint32_t getClassAnnotationsFieldsSizeValueFromIndex(uint nIndex);
    //获取相应Class结构中的class_annotations_off_结构中methods_size_字段值
    uint32_t getClassAnnotationsMethodsSizeValueFromIndex(uint nIndex);
    //获取相应Class结构中的class_annotations_off_结构中parameters_size_字段值
    uint32_t getClassAnnotationsParametersSizeValueFromIndex(uint nIndex);

    
    //根据相应Class结构中的interfaces_off_判断是否需要输出相关信息
    bool isClassNeedShowInterfacesString(uint nIndex);
    //获取相应Class结构中的class_annotations_off_结构数据,返回值需要手动释放
    const char* getClassInterfacesStringFromIndex(uint nIndex);
    //获取指定Class下标的interfaces_off_结构下的list_结构指针
    PSTTypeList getClassInterfaceListSTFromIndex(uint nIndex);   
    //获取指定Class下标的interfaces_off_结构下的list_结构数量
    uint32_t getClassInterfaceListSizeFromIndex(uint nIndex);

	//根据class_def_item->class_data_off_字段值判断是否需要输出
	bool isClassNeedShowClassDataString(uint nIndex);
    //获取相应Class结构中的class_data_off_结构数据,返回值需要手动释放
    const char* getClassClassDataStringFromIndex(uint nIndex);
	//获取指定Class结构中的STClassDataItem结构指定
	PSTClassDataItem getClassClassDataSTFromIndex(uint nIndex);
	//获取指定class_def_item->class_data_off_->static_fields_size字段值，这是LEB128类型数据
	uint32_t getClassClassDataStaticFieldsSizeValueFromIndex(uint nIndex);
	//获取指定class_def_item->class_data_off_->instance_fields_size字段值，这是LEB128类型数据
	uint32_t getClassClassDataInstanceFieldsSizeValueFromIndex(uint nIndex);
	//获取指定class_def_item->class_data_off_->direct_methods_size字段值，这是LEB128类型数据
	uint32_t getClassClassDataDirectMethodsSizeValueFromIndex(uint nIndex);
	//获取指定class_def_item->class_data_off_->virtual_methods_size字段值，这是LEB128类型数据
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
	//获取下一个FieldST的BYTE地址，默认2个LEB128数据为界
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
	BYTE* getClassInstanceFieldsAddrFromIndex(uint nIndex);
	
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
	//获取指定class_def_item->class_data_off_->direct_methods_size指向的数据地址,没有则返回空指针！！！
	BYTE* getClassDirectMethodsAddrFromIndex(uint nIndex);
	
	//指定class_def_item->class_data_off_->virtual_methods_size字段值是否为0
	bool isClassNeedShowVirtualMethodsStringFromIndex(uint nIndex);
	//获取指定class_def_item->class_data_off_->virtual_methods_size字段的字符串,返回值需要手动释放
	const char* getClassVirtualMethodsStringFromIndex(uint nIndex, uint nFieldIndex);
	//获取指定class_def_item->class_data_off_->virtual_methods_size->field_idx_diff字段值,这是一个LEB128数据
	DWORD getClassVirtualMethodsFieldIdxDiffValueIndex(BYTE *pByte);
	//获取指定class_def_item->class_data_off_->virtual_methods_size->access_flags字段值,这是一个LEB128数据
	DWORD getClassVirtualMethodsAccessFlagsValueIndex(BYTE *pByte);
	//获取指定class_def_item->class_data_off_->virtual_methods_size->code_off字段值,这是一个LEB128数据
	DWORD getClassVirtualMethodsCodeOffValueIndex(BYTE *pByte);
	//获取指定class_def_item->class_data_off_->virtual_methods_size指向的数据地址,没有则返回空指针！！！
	BYTE* getClassVirtualMethodsAddrFromIndex(uint nIndex);

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