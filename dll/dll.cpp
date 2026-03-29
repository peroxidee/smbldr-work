// dll.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "dll.h"


// This is an example of an exported variable
DLL_API int ndll=0;

// This is an example of an exported function.
DLL_API int fndll(void)
{
    return 0;
}

// This is the constructor of a class that has been exported.
Cdll::Cdll()
{
    return;
}
