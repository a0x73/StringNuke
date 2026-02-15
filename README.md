# StringNuke

A Windows PE string obfuscation tool that encrypts string literals at the binary level to protect against static analysis and reverse engineering.

![Language](https://img.shields.io/badge/language-C++-blue.svg)

# Features

- Simple XOR - Fast example to show stub and obfuscation logic.
- Custom - Option to add your own custom string obfuscation and stub alongside to solve.
- Only targets your user strings, ignores any system strings

# Support
- This only supports x64 as personally I would never need support for x32 and the assembly stub was horrible as is (more info below)

# NOTE
- For the stub, after a few failed attempts i used handy gemini to fix some stack alignment issues i had (also provided some comments i missed in the stub setup)

### Execution Flow

1. **Startup**: Windows loader starts the protected executable
2. **Entry Point**: Execution begins at the decryption stub (new entry point)
3. **Decryption**: Stub decrypts all strings in memory (takes microseconds)
4. **Jump**: Stub redirects to the original entry point
5. **Runtime**: Program executes normally with decrypted strings
