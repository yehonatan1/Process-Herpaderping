#include "NtdllFunctions.h"

const LPCSTR NTDLL_DLL_NAME = "ntdll.dll";

DLLFunctionsLoader NtdllFunctions::_functionsLoader(NTDLL_DLL_NAME);
NtQueryInformationProcess NtdllFunctions::_NtQueryInformationProcess = (NtQueryInformationProcess)(NtdllFunctions::_functionsLoader["NtQueryInformationProcess"]);
NtCreateSection NtdllFunctions::_NtCreateSection = NtdllFunctions::_functionsLoader["NtCreateSection"];
NtCreateProcessEx NtdllFunctions::_NtCreateProcessEx = NtdllFunctions::_functionsLoader["NtCreateProcessEx"];
NtCreateThreadEx NtdllFunctions::_NtCreateThreadEx = NtdllFunctions::_functionsLoader["NtCreateThreadEx"];
RtlCreateProcessParametersEx NtdllFunctions::_RtlCreateProcessParametersEx = NtdllFunctions::_functionsLoader["RtlCreateProcessParametersEx"];
RtlNtStatusToDosError NtdllFunctions::_RtlNtStatusToDosError = NtdllFunctions::_functionsLoader["RtlNtStatusToDosError"];