#!/usr/bin/python3

import json
import random

import argparse

SEED = random.randint(2 ** 28, 2 ** 32 - 1)

def get_function_hash(function_name):
    h = SEED
    name = function_name.replace('Nt', 'Zw', 1)
    ror8 = lambda v: ((v >> 8) & (2 ** 32 - 1)) | ((v << 24) & (2 ** 32 - 1))

    for segment in name:
        partial_name_short = ord(segment)
        h ^= partial_name_short + ror8(h)

    return h

def combine_arguments(arguments):
    return ',\n  '.join(
        f'{argument["name"]}: {argument["type"]}'
        for argument in arguments
    )

def generate_function(name, arguments):
    return f'''
proc {name}*({combine_arguments(arguments)}): NTSTATUS {{.asmNoStackFrame.}} =
  asm """
    push rcx
    push rdx
    push r8
    push r9
    sub rsp, 32
    mov rcx, {hex(get_function_hash(name))}
    call FindSyscall
    add rsp, 32
    pop r9
    pop r8
    pop rdx
    pop rcx
    mov r10, rcx
    syscall
    ret
  """
'''     

def get_all_types(types, prototypes, all_functions):
    visited = set()
    param_types = set(
        param["type"]
        for name in all_functions
        for param in prototypes[name]["params"]
    )

    def get_all_definitions(identifiers):
        while identifiers:
            i = identifiers.pop()
            if i in visited:
                continue
            visited.add(i)

            for type in types:
                if type["identifier"] == i:
                    depencies = set(d for d in type["dependencies"])
                    yield from get_all_definitions(depencies)
                    yield type["definition"]
        yield None
    yield from get_all_definitions(param_types)

def generate(allowed_functions, outf, _filter=False):
    with open("./data/base.nim", "r") as basef, \
         open(f"./out/{outf}.nim", "w") as whisperf, \
         open("./data/prototypes.json", "r") as protf, \
         open("./data/types.json", "r") as typesf:
        base = basef.read()

        # Replace seed
        base = base.replace("###SEED###", f"const seed = int64({hex(SEED)})")

        # Replace functions
        prototypes = json.load(protf)
        all_functions = [
            name
            for name in prototypes
            if name in allowed_functions or not _filter
        ]

        functions = "\n".join(
            generate_function(name, prototypes[name]["params"])
            for name in all_functions
        )
        base = base.replace("###FUNCTIONS###", functions)

        # Replace types
        types = json.load(typesf)
        definitions = "\n\n".join(
            definition
            for definition in get_all_types(types, prototypes, all_functions)
            if not definition is None
        )
        base = base.replace("###TYPES###", definitions)

        print(f"[*] Done, written to ./out/{outf}.nim")
        whisperf.write(base)

if __name__ == "__main__":
    print("""
 _______  .__        __      __.__    .__                                    
 \      \ |__| _____/  \    /  \  |__ |__| ____________   ___________  ______
 /   |   \|  |/     \   \/\/   /  |  \|  |/  ___/\____ \_/ __ \_  __ \/  ___/
/    |    \  |  Y Y  \        /|   Y  \  |\___ \ |  |_> >  ___/|  | \/\___ \ 
\____|__  /__|__|_|  /\__/\  / |___|  /__/____  >|   __/ \___  >__|  /____  >
        \/         \/      \/       \/        \/ |__|        \/           \/ 

@SECFORCE_LTD
""")

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--preset', help='Preset ("all", "common")', required=False)
    parser.add_argument('-f', '--functions', help='Comma-separated functions', required=False)
    parser.add_argument('-o', '--out-file', help='Output basename (w/o extension)', required=True)
    args = parser.parse_args()

    if args.preset == 'all':
        print("[*] Generating ALL functions")
        generate([], args.out_file)

    elif args.preset == 'common':
        print("[*] Generating Common functions")
        generate(
            {'NtCreateProcess',
             'NtCreateThreadEx',
             'NtOpenProcess',
             'NtOpenProcessToken',
             'NtTestAlert',
             'NtOpenThread',
             'NtSuspendProcess',
             'NtSuspendThread',
             'NtResumeProcess',
             'NtResumeThread',
             'NtGetContextThread',
             'NtSetContextThread',
             'NtClose',
             'NtReadVirtualMemory',
             'NtWriteVirtualMemory',
             'NtAllocateVirtualMemory',
             'NtProtectVirtualMemory',
             'NtFreeVirtualMemory',
             'NtQuerySystemInformation',
             'NtQueryDirectoryFile',
             'NtQueryInformationFile',
             'NtQueryInformationProcess',
             'NtQueryInformationThread',
             'NtCreateSection',
             'NtOpenSection',
             'NtMapViewOfSection',
             'NtUnmapViewOfSection',
             'NtAdjustPrivilegesToken',
             'NtDeviceIoControlFile',
             'NtQueueApcThread',
             'NtWaitForMultipleObjects'},
            args.out_file,
            _filter=True
        )
    elif args.preset:
        parser.error('\n[!] Invalid preset provided. Must be "all" or "common".')

    elif not args.functions:
        parser.error("""\n[!] Either functions or preset must be specified.
EXAMPLE: ./nimwhispers.py --preset common --out-file nimwhispers')
EXAMPLE: ./nimwhispers.py --functions NtTestAlert,NtGetCurrentProcessorNumber --out-file nimwhispers""")

    else:
        functions = args.functions.split(',') if args.functions else []
        print(f"[*] Generating the following functions {args.functions}")
        generate(functions, args.out_file, _filter=True)