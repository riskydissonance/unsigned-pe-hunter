# Unsigned PE Hunter

Search for unsigned PEs (.dlls and .exes) on disk, verifying the signature using [WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust).

## Usage

```
unsigned-pe-hunter <directory to recursively search> [int x where find files in last x days]
```
