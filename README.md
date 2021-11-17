# NimWhispers (SysWhispersV2)

NimWhispers helps with evasion by generating nim implants that can be used to make direct syscalls based on the work of SysWhispersv2

## Installation

Ensure that nim is installed and mingw if cross compiling from linux

```
git clone https://github.com/SECFORCE/NimWhispers.git
cd NimWhispers
python3 nimwhispers.py
```

## Usage

```

 _______  .__        __      __.__    .__                                    
 \      \ |__| _____/  \    /  \  |__ |__| ____________   ___________  ______
 /   |   \|  |/     \   \/\/   /  |  \|  |/  ___/\____ \_/ __ \_  __ \/  ___/
/    |    \  |  Y Y  \        /|   Y  \  |\___ \ |  |_> >  ___/|  | \/\___ \ 
\____|__  /__|__|_|  /\__/\  / |___|  /__/____  >|   __/ \___  >__|  /____  >
        \/         \/      \/       \/        \/ |__|        \/           \/ 

@SECFORCE_LTD

usage: nimwhispers.py [-h] [-p PRESET] [-f FUNCTIONS] -o OUT_FILE

optional arguments:
  -h, --help            show this help message and exit
  -p PRESET, --preset PRESET
                        Preset ("all", "common")
  -f FUNCTIONS, --functions FUNCTIONS
                        Comma-separated functions
  -o OUT_FILE, --out-file OUT_FILE
                        Output basename (w/o extension)
```

## Demo

First run

```
python3 nimwhispers.py -o nimwhispers -f NtOpenProcess,NtAllocateVirtualMemory,NtWriteVirtualMemory,NtProtectVirtualMemory,NtCreateThreadEx
```

There will be a new file nimwhispers.nim in the out directory that contains the asm stubs to run the example.

Afterwards compile the binary

## Compilation

**Windows**

```
nim c example.nim
```

**Linux**

```
nim c --cpu:amd64 -d:mingw --os:windows --gcc.exe:x86_64-w64-mingw32-gcc --gcc.linkerexe:x86_64-w64-mingw32-gcc example.nim
```

Then run it on any window machine and a meterpreter messagebox should be shown

## Caveats

- Only works on x64!
- Not everything is Tested (USE AT YOUR OWN RISK)
