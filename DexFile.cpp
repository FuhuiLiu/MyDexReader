#include "StdAfx.h"
#include "DexFile.h"

//��ӦMapItem->type�ĺ����ַ���
const char* g_MapItemName[] = {
    "kDexTypeHeaderItem",
    "kDexTypeStringIdItem",
    "kDexTypeTypeIdItem",
    "kDexTypeProtoIdItem",
    "kDexTypeFieldIdItem",
    "kDexTypeMethodIdItem",
    "kDexTypeClassDefItem",
    "kDexTypeMapList",
    "kDexTypeTypeList",
    "kDexTypeAnnotationSetRefList",
    "kDexTypeAnnotationSetItem",
    "kDexTypeClassDataItem",
    "kDexTypeCodeItem",
    "kDexTypeStringDataItem",
    "kDexTypeDebugInfoItem",
    "kDexTypeAnnotationItem",
    "kDexTypeEncodedArrayItem",
    "kDexTypeAnnotationsDirectoryItem",
};

///////////////////////////////////////////////////////////////////////////
/* �������ܣ���ȡ��ӦMapItem->type�ĺ����ַ���
 * ��������: Ҫ�õĶ�Ӧ�±�
 * ��������ֵ����Ӧ�ַ���ָ�� 
 */
///////////////////////////////////////////////////////////////////////////
const char* getMapItemName(uint nIndex)
{
    switch(nIndex)
    {
    case kDexTypeMapList:             //0x1000
        nIndex = 7;
        break;
    case kDexTypeTypeList:            // 0x1001
        nIndex = 8;
        break;
    case kDexTypeAnnotationSetRefList:    //0x1002
        nIndex = 9;
        break;
    case kDexTypeAnnotationSetItem:   //0x1003
        nIndex = 10;
        break;
    case kDexTypeClassDataItem:       // 0x2000:
        nIndex = 11;
        break;
    case kDexTypeCodeItem:            //0x2001:
        nIndex = 12;
        break;
    case kDexTypeStringDataItem:      //0x2002:
        nIndex = 13;
        break;
    case kDexTypeDebugInfoItem:       // 0x2003:
        nIndex = 14;
        break;
    case kDexTypeAnnotationItem:      // 0x2004:
        nIndex = 15;
        break;
    case kDexTypeEncodedArrayItem:    // 0x2005:
        nIndex = 16;
        break;
    case kDexTypeAnnotationsDirectoryItem:    // 0x2006:
        nIndex = 17;
        break;
    default:
        break;
    }
    return g_MapItemName[nIndex];
}

// uint32_t g_AccessFlags[] = {
//     kAccPublic,
//     kAccPrivate,
//     kAccProtected,
//     kAccStatic,
//     kAccFinal,
//     kAccSynchronized,
//     kAccSuper,
//     kAccVolatile,
//     kAccBridge,
//     kAccTransient,
//     kAccVarargs,
//     kAccNative,
//     kAccInterface,
//     kAccAbstract,
//     kAccStrict,
//     kAccSynthetic,
//     kAccAnnotation,
//     kAccEnum,
//     kAccMiranda,
//     //kAccJavaFlagsMask,
//     kAccConstructor,
//     kAccDeclaredSynchronized,
//     kAccClassIsProxy,
//     kAccPreverified,
//     kAccClassIsFinalizable,
//     kAccClassIsReference,
//     kAccClassIsWeakReference,
//     kAccClassIsFinalizerReference,
//     kAccClassIsPhantomReference,
// };