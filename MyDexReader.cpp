// MyDexReader.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "MyDexShowUtils.h"

int main(int argc, char* argv[])
{
//     int chAry[] = {0x1, 0x33, 0x2, 0x9, 0x83};
//     printf("chAryLen= %d\r\n", sizeof(chAry) / sizeof(chAry[0]));

    MyDexShowUtils *pST = new MyDexShowUtils();
    bool bRet = pST->init(argv[1]);
    if (bRet)
    {
        pST->showAllString();
        pST->showAllType();
        pST->showAllProto();
		pST->showAllFields();
		pST->showAllMethods();
		pST->showAllClasses();
    }
    else
        printf("not dex035 file!\r\n");

	return 0;
}

