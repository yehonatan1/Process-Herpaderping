#pragma once

#include <Windows.h>
#include "ProcedurePointer.h"

class DLLFunctionsLoader
{
public:
    explicit DLLFunctionsLoader(LPCSTR dllName);
    ~DLLFunctionsLoader();

    ProcedurePointer operator[](LPCSTR procedureName) const;

private:
    HMODULE _module;
};