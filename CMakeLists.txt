cmake_minimum_required(VERSION 3.19)
project(Process_Herpaderping)

set(CMAKE_CXX_STANDARD 20)

add_executable(Process_Herpaderping main.cpp NtdllFunctions.cpp NtdllFunctions.h DLLFunctionsLoader.cpp DLLFunctionsLoader.h ProcedurePointer.cpp ProcedurePointer.h)