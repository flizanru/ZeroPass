@echo off
setlocal
if "%~1"=="" exit /b 2
call "%~1"
if errorlevel 1 exit /b 1
pushd "%~dp0"
link /nologo /DLL /MACHINE:X64 /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /CETCOMPAT /BREPRO /OPT:REF /OPT:ICF /DEF:exports.def /OUT:libsodium.dll /IMPLIB:linked-import.lib upstream-static.lib advapi32.lib
set result=%errorlevel%
popd
exit /b %result%
