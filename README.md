# CE-DMAPlugin

DMA Plugin for Cheat Engine.

## Features

- Process Attaching
- Module Enumerations
- Memory Scanning
- Memory Read
- Memory Write (works, but not recommended to use)
- Pointer Map Generation
- Pointer Scanning

- Debugger Attaching is not supported

## Build

VS2022

## How to Use

Important Note: Since the current cheat engine sdk does not export the `isWow64Process` function, this plugin only works with cheat engine with customized sdk.

- Download the latest release in [cheatengine-extended-sdk](https://github.com/kaijia2022/cheatengine-extended-sdk)

- Place the `CE-DMAPlugin.dll`, `FTD3XX.dll`, `leechcore.dll` and `vmm.dll` in the same level as `Cheat Engine.exe` (these files should already be included in the folder with the required file structure, but just in case anyone wants to compile their own version)

- Open cheat engine, go to Settings -> Plugins -> Add New, and locate `CE-DMAPlugin.dll`.

