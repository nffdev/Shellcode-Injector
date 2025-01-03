# Shellcode-Injector
A tool for injecting shellcode into target processes on Windows for testing.

## Requirements
- Visual Studio 2019 or higher
- Windows SDK (for access to Windows APIs)

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/nffdev/Shellcode-Injector.git
   ```
2. Open the project in Visual Studio.
3. Compile the project using the `Release` or `Debug` configuration.

## Use 

1. Compile and run the application.
2. Enter the PID (Process ID) of the target process you wish to inject the shellcode into.
3. The application will inject the shellcode into the specified process and create a remote thread to execute it.

## TECHNICAL DETAILS

![image](https://raw.githubusercontent.com/nffdev/Shellcode-Injector/refs/heads/main/shellcode-injector.png)

- **OpenProcess**: Opens the target process with `PROCESS_ALL_ACCESS` to enable memory manipulation and thread creation.
- **VirtualAllocEx**: Allocates memory within the target process to store the shellcode.
- **WriteProcessMemory**: Writes the shellcode into the allocated memory space in the target process.
- **CreateRemoteThreadEx**: Creates a remote thread in the target process to execute the shellcode.
- **LogHex**: Utility function to log memory addresses in a human-readable hexadecimal format.

## Resources

- [Official Microsoft documentation on Windows APIs](https://docs.microsoft.com/en-us/windows/win32/)

## Demo

![Demo](https://raw.githubusercontent.com/nffdev/Shellcode-Injector/main/demo.gif)
