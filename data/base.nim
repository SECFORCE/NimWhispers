{.passC:"-masm=intel".}
{.passC:"-fomit-frame-pointer".}

import cstrutils
import algorithm
import winim/lean

###TYPES###

template RVA2VA(casttype, dllbase, rva: untyped): untyped =
  cast[casttype](cast[ULONG_PTR](dllbase) + rva)

proc `+`[T](a: ptr T, b: int): ptr T =
    cast[ptr T](cast[uint](a) + cast[uint](b * a[].sizeof))

type SYSCALL_ENTRY = tuple[name: int64, address: DWORD]
var syscalllist = newSeq[SYSCALL_ENTRY]()

###SEED###

template ROR8(v: int64): int64 =
  ((v shr 8 and 4294967295) or (v shl 24 and 4294967295))

proc hashSyscall(funcname: cstring): int64 =
    var hash = seed
    for letter in funcname:
        hash = hash xor int64(letter) + ROR8(hash)
    return hash

proc GetPPEB(p: culong): P_PEB {. 
    header: 
        """#include <windows.h>
           #include <winnt.h>""", 
    importc: "__readgsqword"
.}

proc CompareSyscalls(a, b: SYSCALL_ENTRY): int = 
    if a.address < b.address: -1
    else: 1

proc GetSycallList() =
    var peb = GetPPEB(0x60)
    var dllname: cstring
    var exportdir: PIMAGE_EXPORT_DIRECTORY
    var dllbase: PVOID

    var ldr_entry = cast[PLDR_DATA_TABLE_ENTRY](peb.Ldr.Reserved2[1])
    while ldr_entry.DllBase != nil:
        dllbase = ldr_entry.DllBase
        var dosheader = cast[PIMAGE_DOS_HEADER](dllbase)
        var ntheader = RVA2VA(PIMAGE_NT_HEADERS, dllbase, dosheader.e_lfanew)
        var virtaddress = ntheader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
        if virtaddress == 0:
            ldr_entry = cast[P_LDR_DATA_TABLE_ENTRY](ldr_entry.Reserved1[0])
            continue

        exportdir = RVA2VA(PIMAGE_EXPORT_DIRECTORY, dllbase, virtaddress)
        dllname = RVA2VA(cstring, dllbase, exportdir.Name)
        if dllname == cstring("ntdll.dll"):
            break

    var numofnames = cast[DWORD](exportdir.NumberOfNames)
    var functions = RVA2VA(PDWORD, dllbase, exportdir.AddressOfFunctions)
    var names = RVA2VA(PDWORD, dllbase, exportdir.AddressOfNames)[]
    var ordinals = RVA2VA(PWORD, dllbase, exportdir.AddressOfNameOrdinals)

    for i in 0 .. numofnames:
        var funcname = RVA2VA(cstring, dllbase, names)
        var funcaddr = functions + cast[int](ordinals[])
        names += cast[DWORD](len(funcname) + 1)
        ordinals = ordinals + 1
        
        if funcname.startswith("Zw"):
            var entry: SYSCALL_ENTRY
            entry = (name: hashSyscall(funcname), address: funcaddr[])
            syscalllist.add(entry)

    syscalllist.sort(CompareSyscalls)

proc FindSyscall(name: int64): DWORD {.exportc: "FindSyscall".} =
    for i in 0 .. syscalllist.len - 1:
        if syscalllist[i].name == name:
            return cast[DWORD](i)
    return cast[DWORD](-1)

###FUNCTIONS###

GetSycallList()