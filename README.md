# Windows Direct Syscall Implementation
### Created by FURYWOLF
Special thanks to @Hxnter999 for the help with assembly code!

## Overview
This project provides a direct Windows syscall implementation that dynamically resolves syscall IDs at runtime. It's designed to be stealthy and efficient.

## Features
- Dynamic syscall ID resolution at runtime
- Fully written in C++
- Customizable syscall table
- Using masm to do execute our syscall
- PE parsing, getting the syscall ID directly from the file on disk, to avoid Byte patching in runtime memory.

## Requirements
- Windows operating system
- Visual Studio 2019 or later (with MSVC compiler)
- MASM (Microsoft Macro Assembler)



## Current usage
- Memory Management
  - NtAllocateVirtualMemory
  
# TODO :
- Add more syscalls 
- Fix bugs & issues.

# Remember, this code is NOT perfect, and requires some optimisation, especially on the assmebly part

## Usage Example
```cpp
#include "syscalls.hpp"
#include <iostream>

int main() {
    // Initialize the syscall subsystem
    if (!Syscalls::Initialize()) {
        std::cerr << "Failed to initialize syscall subsystem\n";
        return 1;
    }

    // Example: Allocate virtual memory
    void* baseAddress = nullptr;
    SIZE_T regionSize = 0x1000;

    auto status = Syscalls::Call("NtAllocateVirtualMemory",
        GetCurrentProcess(),
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    // Check results
    std::cout << "Status: " << std::hex << status << std::endl;
    std::cout << "Allocated address: " << baseAddress << std::endl;

    // Don't forget cleanup!
    Syscalls::Cleanup();
    return 0;
}
```

## Credits
- Main implementation by FURYWOLF
- Assembly assistance from @Hxnter999


## Notes
- This is meant for educational and research purposes
- Make sure you understand system programming before using
- Use responsibly!

## Coming Soon
- [ ] More syscall implementations
- [ ] Extended error handling
- [ ] Additional usage examples
- [ ] Documentation improvements

## Contributing
Feel free to:
- Report issues
- Suggest improvements
- Submit pull requests
- Share your experiences

## License

MIT License

Copyright (c) 2024 FURYWOLF

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

