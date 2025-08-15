using System;
using System.IO;
using System.Linq;
using System.Text;

namespace E6EFF8A0
{
    class Program
    {
        // Magic constants
        const uint MAGIC_V1 = 0xA0F8EFE6; // -1594298394 signed
        const uint MAGIC_V2 = 0xE3F8EFE6; // -470224922 signed

        // Defaults
        static int EncryptionMethod = 2;   // dword_404018 (1 or 2). default = 2
        static int FileVersion = 1;        // dword_40401C (1 or 2). default = 1
        static uint EncryptionKey = 0;     // dword_404380 (must be provided to encrypt)
        static bool InfoOnly = false;      // byte_404384 (-i)
        static bool CreateBackup = true;   // byte_404020 (true by default, -n disables)

        static int Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;

            if (args.Length <= 0)
            {
                PrintHelp();
                return 0;
            }

            // parse args
            if (!ParseArgs(args))
            {
                Console.WriteLine("Failed to parse arguments.");
                return -1;
            }

            string path = args[0];
            if (!File.Exists(path))
            {
                Console.Error.WriteLine("ERROR: Can't open input file");
                return -1;
            }

            byte[] input;
            try { input = File.ReadAllBytes(path); }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"ERROR: Can't read input file: {ex.Message}");
                return -1;
            }

            // detect header
            if (input.Length < 4)
            {
                Console.WriteLine("This file is not encrypted.");
                return 0;
            }

            uint firstDword = ReadUInt32LE(input, 0);
            bool isEncrypted = (firstDword == MAGIC_V1 || firstDword == MAGIC_V2);
            int detectedVersion = isEncrypted
                ? (firstDword == MAGIC_V1 ? 1 : 2)
                : 0;

            if (!isEncrypted)
            {
                if (EncryptionKey == 0 || InfoOnly)
                {
                    Console.WriteLine("This file is not encrypted.");
                    return 0;
                }

                // create backup if requested
                if (CreateBackup)
                {
                    try
                    {
                        File.WriteAllBytes(path + ".bak", input);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Unable to make backup! " + ex.Message);
                    }
                }

                // Encrypt: produce new buffer with header + encrypted payload
                byte[] encrypted;
                if (EncryptionMethod == 1)
                    encrypted = EncryptWithHeaderMethod1(input, EncryptionKey, FileVersion);
                else // method 2 or any other -> method 2
                    encrypted = EncryptWithHeaderMethod2(input, EncryptionKey, FileVersion);

                try
                {
                    File.WriteAllBytes(path, encrypted);
                    Console.WriteLine("File Encrypted!");
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("ERROR: Can't write an output result: " + ex.Message);
                    return -2;
                }

                return 0;
            }
            else
            {
                // Encrypted file handling
                uint keyFromHeader = ReadUInt32LE(input, 4);
                Console.WriteLine($"File Version = {detectedVersion}");
                Console.WriteLine($"Encryption key = 0x{keyFromHeader:X}");

                if (InfoOnly)
                    return 0;

                Console.WriteLine($"Encryption method = {EncryptionMethod}");

                // backup encrypted original if requested
                if (CreateBackup)
                {
                    try
                    {
                        File.WriteAllBytes(path + ".bak", input);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Unable to make backup! " + ex.Message);
                    }
                }

                // decrypt payload depending on header layout
                byte[] decrypted;
                try
                {
                    if (detectedVersion == 1)
                    {
                        // header: [magic:4][key:4][payload...]
                        int payloadOffset = 8;
                        int payloadLen = input.Length - payloadOffset;
                        if (payloadLen < 0) payloadLen = 0;
                        byte[] payload = new byte[payloadLen];
                        Array.Copy(input, payloadOffset, payload, 0, payloadLen);

                        decrypted = (EncryptionMethod == 1)
                            ? ProcessMethod1(payload, keyFromHeader)
                            : ProcessMethod2(payload, keyFromHeader);
                    }
                    else // version 2
                    {
                        // header: [magic:4][key:4][size1:4][size2:4][payload...]
                        if (input.Length < 16)
                        {
                            Console.Error.WriteLine("ERROR: Corrupt file (too small for v2 header).");
                            return -3;
                        }

                        uint size1 = ReadUInt32LE(input, 8);
                        uint size2 = ReadUInt32LE(input, 12);
                        if (size1 != size2)
                        {
                            Console.WriteLine("WARNING: size fields are not equal! The result might be incorrect!");
                        }

                        int payloadOffset = 16;
                        int payloadLen = (int)size1;
                        if (payloadOffset + payloadLen > input.Length)
                        {
                            // If reported size is inconsistent with file length, clamp to available data
                            payloadLen = Math.Max(0, input.Length - payloadOffset);
                        }

                        byte[] payload = new byte[payloadLen];
                        Array.Copy(input, payloadOffset, payload, 0, payloadLen);

                        decrypted = (EncryptionMethod == 1)
                            ? ProcessMethod1(payload, keyFromHeader)
                            : ProcessMethod2(payload, keyFromHeader);
                    }
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("ERROR during decryption: " + ex.Message);
                    return -4;
                }

                // write decrypted content back to same file
                try
                {
                    File.WriteAllBytes(path, decrypted);
                    Console.WriteLine("File Decrypted!");
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("ERROR: Can't write an output result: " + ex.Message);
                    return -2;
                }

                return 0;
            }
        }

        // -------------------------
        // Helper: parse args like original (-k <key>, -eX, -vX, -i, -n)
        // -------------------------
        static bool ParseArgs(string[] args)
        {
            // first arg is file path, options follow (original program used argv starting from index 1 for options)
            // but the decompiled main used argv[1] as file and parse_args used argv & argc directly. We'll support both:
            // If only one arg (file) then no options. If more args present parse them from index 1 onward.
            for (int i = 1; i < args.Length; ++i)
            {
                string a = args[i];
                if (string.IsNullOrEmpty(a)) continue;
                if (!a.StartsWith("-") && !a.StartsWith("/")) continue; // ignore non-option

                char opt = a.Length >= 2 ? a[1] : '\0';
                switch (opt)
                {
                    case 'e':
                    case 'E':
                        // -eX where X is digit indicating method
                        if (a.Length >= 3 && int.TryParse(a.Substring(2), out int em))
                        {
                            EncryptionMethod = em;
                            if (EncryptionMethod < 1 || EncryptionMethod > 2) EncryptionMethod = 2;
                        }
                        break;

                    case 'v':
                    case 'V':
                        if (a.Length >= 3 && int.TryParse(a.Substring(2), out int fv))
                        {
                            FileVersion = fv;
                            if (FileVersion < 1 || FileVersion > 2) FileVersion = 1;
                        }
                        break;

                    case 'i':
                    case 'I':
                        InfoOnly = true;
                        break;

                    case 'n':
                    case 'N':
                        CreateBackup = false;
                        break;

                    case 'k':
                    case 'K':
                        // original used next argv as key. Support both "-k" then next and "-kVALUE"
                        string val = null;
                        if (a.Length > 2)
                        {
                            val = a.Substring(2);
                        }
                        else
                        {
                            if (i + 1 < args.Length)
                            {
                                val = args[++i];
                            }
                        }
                        if (!string.IsNullOrEmpty(val))
                        {
                            if (val.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                            {
                                if (uint.TryParse(val.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out uint hv))
                                    EncryptionKey = hv;
                            }
                            else
                            {
                                if (uint.TryParse(val, out uint dv))
                                    EncryptionKey = dv;
                            }
                        }
                        break;

                    default:
                        // ignore unknown option
                        break;
                }
            }
            return true;
        }

        static void PrintHelp()
        {
            Console.WriteLine("MGS V ResDec v1.0");
            Console.WriteLine("Made by Sergeanur (C# port by DanielSS)");
            Console.WriteLine();
            Console.WriteLine("Usage:");
            Console.WriteLine("  MgsResDec <file> [options]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  -k <key>     Encryption key (decimal or 0x hex). Required for encryption.");
            Console.WriteLine("  -eX          Encryption method (1 or 2). Use -e1 for method 1, -e2 for method 2 (default).");
            Console.WriteLine("  -vX          File version header (1 or 2). Use -v1 for v1 (default), -v2 for v2.");
            Console.WriteLine("  -i           Show only info about file encryption (will not decrypt or encrypt).");
            Console.WriteLine("  -n           Don't create backups (by default .bak is created).");
            Console.WriteLine();
        }

        // -------------------------
        // Read little-endian uint32 from byte array
        // -------------------------
        static uint ReadUInt32LE(byte[] data, int offset)
        {
            if (offset < 0 || offset + 4 > data.Length) return 0;
            return (uint)(data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24));
        }

        static void WriteUInt32LE(byte[] data, int offset, uint value)
        {
            data[offset + 0] = (byte)(value & 0xFF);
            data[offset + 1] = (byte)((value >> 8) & 0xFF);
            data[offset + 2] = (byte)((value >> 16) & 0xFF);
            data[offset + 3] = (byte)((value >> 24) & 0xFF);
        }

        // -------------------------
        // Encryption wrapper that constructs a header (version 1)
        // header layout v1: [magic(4)][key(4)][payload...]
        // -------------------------
        static byte[] EncryptWithHeaderMethod1(byte[] plain, uint key, int version)
        {
            int orig = plain.Length;
            int headerSize = 8;
            if (version == 2) headerSize = 16;
            int total = orig + headerSize;
            byte[] outbuf = new byte[total];

            // magic
            uint magic = (version == 2) ? MAGIC_V2 : MAGIC_V1;
            WriteUInt32LE(outbuf, 0, magic);
            WriteUInt32LE(outbuf, 4, key);

            if (version == 2)
            {
                // store original size in both size fields (as in decompiled code)
                WriteUInt32LE(outbuf, 8, (uint)orig);
                WriteUInt32LE(outbuf, 12, (uint)orig);
            }

            // compute encrypted payload and write at offset headerSize
            byte[] enc = ProcessMethod1(plain, key);
            Array.Copy(enc, 0, outbuf, headerSize, Math.Min(enc.Length, total - headerSize));
            return outbuf;
        }

        // -------------------------
        // Encryption wrapper that constructs a header (version 2 behavior identical except magic)
        // header layout v2: [magic(4)][key(4)][size(4)][size(4)][payload...]
        // -------------------------
        static byte[] EncryptWithHeaderMethod2(byte[] plain, uint key, int version)
        {
            // identical behavior in terms of header fields, but keep separate function for clarity
            return EncryptWithHeaderMethod1(plain, key, version);
        }

        // -------------------------
        // ProcessMethod1: implements sub_4011E0 (method 1 PRNG + XOR)
        // - Processes in 32-bit words (little-endian).
        // - For remaining bytes < 4, copies them unchanged.
        // - Uses uint arithmetic with wrap-around to emulate 32-bit overflow behavior.
        // Constants and update rules taken from decompilation:
        //   seed: v5 = key | ((key ^ 0xFFFFCDEC) << 16)
        //   i = 69069 * key
        //   next: v5 = 3 * (i + 23023 * v5)
        // -------------------------
        static byte[] ProcessMethod1(byte[] src, uint key)
        {
            int len = src.Length;
            byte[] dst = new byte[len];

            uint v5 = unchecked(key | ((key ^ 0xFFFFCDECu) << 16));
            uint i = unchecked((uint)(69069u * key));

            int offset = 0;
            int remaining = len;

            // process 64-byte blocks (16 words)
            while (remaining >= 64)
            {
                for (int j = 0; j < 16; ++j)
                {
                    uint srcWord = ReadUInt32LE(src, offset);
                    uint outWord = unchecked(v5 ^ srcWord);
                    WriteUInt32LE(dst, offset, outWord);
                    v5 = unchecked((uint)(3u * unchecked(i + unchecked(23023u * v5))));
                    offset += 4;
                }
                remaining -= 64;
            }

            // process 16-byte chunks (4 words)
            while (remaining >= 16)
            {
                // unrolled 4 words
                uint s0 = ReadUInt32LE(src, offset);
                uint out0 = unchecked(v5 ^ s0);
                uint v5_n1 = unchecked((uint)(3u * unchecked(i + unchecked(23023u * v5))));
                uint s1 = ReadUInt32LE(src, offset + 4);
                uint out1 = unchecked(v5_n1 ^ s1);
                uint v5_n2 = unchecked((uint)(3u * unchecked(i + unchecked(23023u * v5_n1))));
                uint s2 = ReadUInt32LE(src, offset + 8);
                uint out2 = unchecked(v5_n2 ^ s2);
                uint v5_n3 = unchecked((uint)(3u * unchecked(i + unchecked(23023u * v5_n2))));
                uint s3 = ReadUInt32LE(src, offset + 12);
                uint out3 = unchecked(v5_n3 ^ s3);
                uint v5_next = unchecked((uint)(3u * unchecked(i + unchecked(23023u * v5_n3))));

                WriteUInt32LE(dst, offset + 0, out0);
                WriteUInt32LE(dst, offset + 4, out1);
                WriteUInt32LE(dst, offset + 8, out2);
                WriteUInt32LE(dst, offset + 12, out3);

                v5 = v5_next;
                offset += 16;
                remaining -= 16;
            }

            // process remaining full words (4 bytes)
            while (remaining >= 4)
            {
                uint s = ReadUInt32LE(src, offset);
                uint outw = unchecked(v5 ^ s);
                WriteUInt32LE(dst, offset, outw);
                v5 = unchecked((uint)(3u * unchecked(i + unchecked(23023u * v5))));
                offset += 4;
                remaining -= 4;
            }

            // remaining bytes (less than 4) are copied unchanged
            if (remaining > 0)
            {
                Array.Copy(src, offset, dst, offset, remaining);
            }

            return dst;
        }

        // -------------------------
        // ProcessMethod2: implements sub_4012D0 (method 2 PRNG + XOR)
        // Constants and update rules taken from decompilation:
        //   seed: v5 = key | ((key ^ 0x6576) << 16)
        //   i = 278 * key
        //   next: v5 = i + 48828125 * v5
        // -------------------------
        static byte[] ProcessMethod2(byte[] src, uint key)
        {
            int len = src.Length;
            byte[] dst = new byte[len];

            uint v5 = unchecked(key | ((key ^ 0x6576u) << 16));
            uint i = unchecked((uint)(278u * key));

            int offset = 0;
            int remaining = len;

            // process 64-byte blocks (16 words)
            while (remaining >= 64)
            {
                for (int j = 0; j < 16; ++j)
                {
                    uint srcWord = ReadUInt32LE(src, offset);
                    uint outWord = unchecked(v5 ^ srcWord);
                    WriteUInt32LE(dst, offset, outWord);
                    v5 = unchecked((uint)(i + unchecked(48828125u * v5)));
                    offset += 4;
                }
                remaining -= 64;
            }

            // process in units; decompiled code unrolled into 4-word groups
            while (remaining >= 16)
            {
                uint s0 = ReadUInt32LE(src, offset);
                uint out0 = unchecked(v5 ^ s0);
                uint v1 = unchecked((uint)(i + unchecked(48828125u * v5)));

                uint s1 = ReadUInt32LE(src, offset + 4);
                uint out1 = unchecked(v1 ^ s1);
                uint v2 = unchecked((uint)(i + unchecked(48828125u * v1)));

                uint s2 = ReadUInt32LE(src, offset + 8);
                uint out2 = unchecked(v2 ^ s2);
                uint v3 = unchecked((uint)(i + unchecked(48828125u * v2)));

                uint s3 = ReadUInt32LE(src, offset + 12);
                uint out3 = unchecked(v3 ^ s3);
                uint vnext = unchecked((uint)(i + unchecked(48828125u * v3)));

                WriteUInt32LE(dst, offset + 0, out0);
                WriteUInt32LE(dst, offset + 4, out1);
                WriteUInt32LE(dst, offset + 8, out2);
                WriteUInt32LE(dst, offset + 12, out3);

                v5 = vnext;
                offset += 16;
                remaining -= 16;
            }

            // remaining full words
            while (remaining >= 4)
            {
                uint s = ReadUInt32LE(src, offset);
                uint outw = unchecked(v5 ^ s);
                WriteUInt32LE(dst, offset, outw);
                v5 = unchecked((uint)(i + unchecked(48828125u * v5)));
                offset += 4;
                remaining -= 4;
            }

            // remaining bytes (<4) copied unchanged
            if (remaining > 0)
            {
                Array.Copy(src, offset, dst, offset, remaining);
            }

            return dst;
        }
    }
}
