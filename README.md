# Fox Engine File Decryptor E6EFF8A0

A port of the original **"MGS V ResDec v1.0"** by Sergeanur to C#.  
This tool is used to decrypt (and encrypt) files from the Fox Engine.  
The encrypted files have the hex header E6,EF,F8,A0.  
Used in *Metal Gear Solid V: The Phantom Pain*, *P.T.*, and probably in other games using the Fox Engine.

### Quick Usage Tip:
Drag and drop the file onto the `.exe` for a quick way to decrypt without using the command line.

### Usage:
E6EFF8A0.exe `<file>` [options]

### Options:
- `-k <key>`  Encryption key (decimal or 0x hex). **Required for encryption.**
- `-eX`  Encryption method (1 or 2). Use `-e1` for method 1, `-e2` for method 2 (default).
- `-vX`  File version header (1 or 2). Use `-v1` for v1 (default), `-v2` for v2.
- `-i`  Show only info about file encryption (will not decrypt or encrypt).
- `-n`  Don’t create backups (by default `.bak` is created).


<img width="1920" height="848" alt="image" src="https://github.com/user-attachments/assets/3d91068b-d1a8-41dd-ba53-7f702f54c8fa" />

