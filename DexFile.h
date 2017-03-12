
#if !defined(AFX_DEXFILE_H__20170301_)
#define AFX_DEXFILE_H__20170301_

#include "common/common.h"
#include <string.h>

typedef unsigned char BYTE;
typedef BYTE uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned int uint;

#define kSha1DigestSize 20
#define kDexEndianConstant 0x12345678;
#define EERROR ((BOOL)-1)

//获取对应MapItem->type的含义字符串
extern "C" const char* getMapItemName(uint nIndex);
extern "C" uint32_t g_AccessFlags[];

typedef struct Header{
    uint8_t magic_[8];
    uint32_t checksum_;  // See also location_checksum_
    uint8_t signature_[kSha1DigestSize];
    uint32_t file_size_;  // size of entire file
    uint32_t header_size_;  // offset to start of next section
    uint32_t endian_tag_;
    uint32_t link_size_;  // unused
    uint32_t link_off_;  // unused
    uint32_t map_off_;  // offset of map_list_type
    uint32_t string_ids_size_;  // number of StringIds
    uint32_t string_ids_off_;  // file offset of StringIds array
    uint32_t type_ids_size_;  // number of TypeIds, we don't support more than 65535
    uint32_t type_ids_off_;  // file offset of TypeIds array
    uint32_t proto_ids_size_;  // number of ProtoIds, we don't support more than 65535
    uint32_t proto_ids_off_;  // file offset of ProtoIds array
    uint32_t field_ids_size_;  // number of FieldIds
    uint32_t field_ids_off_;  // file offset of FieldIds array
    uint32_t method_ids_size_;  // number of MethodIds
    uint32_t method_ids_off_;  // file offset of MethodIds array
    uint32_t class_defs_size_;  // number of ClassDefs
    uint32_t class_defs_off_;  // file offset of ClassDef array
    uint32_t data_size_;  // unused
    uint32_t data_off_;  // unused
} STHeader;

// Map item type codes. 
enum EMMapItemType{
    kDexTypeHeaderItem               = 0x0000,
    kDexTypeStringIdItem             = 0x0001,
    kDexTypeTypeIdItem               = 0x0002,
    kDexTypeProtoIdItem              = 0x0003,
    kDexTypeFieldIdItem              = 0x0004,
    kDexTypeMethodIdItem             = 0x0005,
    kDexTypeClassDefItem             = 0x0006,
    kDexTypeMapList                  = 0x1000,
    kDexTypeTypeList                 = 0x1001,
    kDexTypeAnnotationSetRefList     = 0x1002,
    kDexTypeAnnotationSetItem        = 0x1003,
    kDexTypeClassDataItem            = 0x2000,
    kDexTypeCodeItem                 = 0x2001,
    kDexTypeStringDataItem           = 0x2002,
    kDexTypeDebugInfoItem            = 0x2003,
    kDexTypeAnnotationItem           = 0x2004,
    kDexTypeEncodedArrayItem         = 0x2005,
    kDexTypeAnnotationsDirectoryItem = 0x2006,
} ;

typedef struct MAPITEM {
    uint16_t type_;     //指示这个MAPITEM类型
    uint16_t unused_;   //unused
    uint32_t size_;     //类型个数
    uint32_t offset_;   //在文件中的偏移
} STMapItem;

// 由DexHeader中的map_off字段指定在文件中的偏移 = header->map_off
typedef struct MAPINFO
{
   uint m_nSize; //指示有多少个MapItem结构
   STMapItem m_MapItem[1]; //MapItem结构
} STMapInfo;

typedef struct STRING_ID_ITEM
{
    uint m_nOffset; //基于文件的偏移
} STStringIdItem;

// Raw type_id_item. 类型表
typedef struct TypeId {
    uint32_t descriptor_idx_;  // 基于string_ids的下标
} STTypeIdItem;

// Raw proto_id_item. 函数类型表
typedef struct ProtoId {
    uint32_t shorty_idx_;       // 极简模式返回值跟参数表：基于string_ids的下标
    uint16_t return_type_idx_;  // 返回值原始类型，基于type_ids的下标
    uint16_t pad_;              // padding = 0，用于填充对齐4字节
    uint32_t parameters_off_;   // 参数列表文件指针
} STProtoIdItem;

// Raw type_item. TypeItem数组元素
typedef struct TypeItem {
    uint16_t type_idx_;         // 基于type_ids的下标
} STTypeItem;

// Raw type_list. ProtoId结构中的参数类型指针实际结构
typedef struct TypeList {
    uint32_t size_;             //指示其后list实际Item数量
    TypeItem list_[1];          //TypeItem数组
} STTypeList, *PSTTypeList;

// Raw field_id_item.  字段类型
typedef struct FieldId {
    uint16_t class_idx_;  // index into type_ids_ array for defining class
    uint16_t type_idx_;  // index into type_ids_ array for field type
    uint32_t name_idx_;  // index into string_ids_ array for field name
} STFieldIdItem;

// Raw method_id_item. 方法类型
typedef struct MethodId {
    uint16_t class_idx_;  // index into type_ids_ array for defining class
    uint16_t proto_idx_;  // index into proto_ids_ array for method prototype
    uint32_t name_idx_;  // index into string_ids_ array for method name
} STMethodIdItem;

// Raw class_def_item. 类信息
typedef struct ClassDef {
    uint16_t class_idx_;  // index into type_ids_ array for this class
    uint16_t pad1_;  // padding = 0
    uint32_t access_flags_;
    uint16_t superclass_idx_;  // index into type_ids_ array for superclass
    uint16_t pad2_;  // padding = 0
    uint32_t interfaces_off_;  // file offset to TypeList
    uint32_t source_file_idx_;  // index into string_ids_ for source file name
    uint32_t annotations_off_;  // file offset to annotations_directory_item
    uint32_t class_data_off_;  // file offset to class_data_item
    uint32_t static_values_off_;  // file offset to EncodedArray
} STClassDefItem;

#define kAccPublic 0x0001   // class, field, method, ic
#define kAccPrivate 0x0002   // field, method, ic
#define kAccProtected 0x0004   // field, method, ic
#define kAccStatic 0x0008   // field, method, ic
#define kAccFinal 0x0010   // class, field, method, ic
#define kAccSynchronized 0x0020   // method (only allowed on natives)
#define kAccSuper 0x0020   // class (not used in dex)
#define kAccVolatile 0x0040   // field
#define kAccBridge 0x0040   // method (1.5)
#define kAccTransient 0x0080   // field
#define kAccVarargs 0x0080   // method (1.5)
#define kAccNative 0x0100   // method
#define kAccInterface 0x0200   // class, ic
#define kAccAbstract 0x0400   // class, method, ic
#define kAccStrict 0x0800   // method
#define kAccSynthetic 0x1000   // field, method, ic
#define kAccAnnotation 0x2000   // class, ic (1.5)
#define kAccEnum 0x4000   // class, field, ic (1.5)

#define kAccMiranda   0x8000  // method

//#define kAccJavaFlagsMask   0xffff  // bits set from Java sources (low 16)

#define kAccConstructor   0x00010000  // method (dex only) <init> and <clinit>
#define kAccDeclaredSynchronized   0x00020000  // method (dex only)
#define kAccClassIsProxy   0x00040000  // class (dex only)
#define kAccPreverified   0x00080000  // method (dex only)

// Special runtime-only flags.
// Note: if only kAccClassIsReference is set, we have a soft reference.
#define kAccClassIsFinalizable          0x80000000  // class/ancestor overrides finalize()
#define kAccClassIsReference            0x08000000  // class is a soft/weak/phantom ref
#define kAccClassIsWeakReference        0x04000000  // class is a weak reference
#define kAccClassIsFinalizerReference   0x02000000  // class is a finalizer reference
#define kAccClassIsPhantomReference     0x01000000  // class is a phantom reference

////////////////////////////////////////////////////////////////Annotations
typedef struct AnnotationsDirectoryItem {
    uint32_t class_annotations_off_;    //指向AnnotationSetItem结构的文件指针
    uint32_t fields_size_;
    uint32_t methods_size_;
    uint32_t parameters_size_;
} STAnnotationsDirectoryItem, *pSTAnnotationsDirectoryItem;

typedef struct AnnotationSetItem {
    uint32_t size_;
    uint32_t entries_[1];
} STAnnotationSetItem, *pSTAnnotationSetItem;
////////////////////////////////////////////////////////////////Annotations

// class_def_item->class_data_off_ 这几个字段都是LEB128表示
typedef struct ClassDataHeader {
    uint32_t static_fields_size_;  // the number of static fields
    uint32_t instance_fields_size_;  // the number of instance fields
    uint32_t direct_methods_size_;  // the number of direct methods
    uint32_t virtual_methods_size_;  // the number of virtual methods
  } STClassDataItem, *pSTClassDataItem;

// Raw code_item.
typedef struct CodeItem {
    uint16_t registers_size_;
    uint16_t ins_size_;
    uint16_t outs_size_;
    uint16_t tries_size_;
    uint32_t debug_info_off_;  // file offset to debug info stream
    uint32_t insns_size_in_code_units_;  // size of the insns array, in 2 byte code units
    uint16_t insns_[1];
} STCodeItem, *pSTCodeItem;
#endif