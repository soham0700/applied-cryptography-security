# Applied Cryptography & Security

Three small, from-scratch Java implementations built for a computer security course at Binghamton University, covering symmetric encryption, steganography, and a classic memory-safety exploit.

## Salsa20Cipher.java

A from-scratch implementation of the **Salsa20 stream cipher** (64/128/256-bit keys), including the quarter-round, double-round, and key-expansion functions defined in the Salsa20 spec.

```bash
javac Salsa20Cipher.java
java Salsa20Cipher 256 <64-hex-char key> <16-hex-char nonce> <hex plaintext>
```

## SteganographyExtractor.java

Extracts a hidden payload from the least-significant bit of each byte in a carrier file, using a simple custom encoding: a header, an indicator pattern that marks the file as containing hidden data, a length field, and the payload itself, each one bit per carrier byte.

```bash
javac SteganographyExtractor.java
java SteganographyExtractor carrier_file.bmp recovered_output.bin
```

## BufferOverflowAttackGenerator.java

Builds a "smash the stack" style attack string — a filler buffer followed by a target return address — for use against a deliberately vulnerable sample binary in a sandboxed course lab exercise on stack-based buffer overflows.

```bash
javac BufferOverflowAttackGenerator.java
java BufferOverflowAttackGenerator 0x08049213
```

**Note:** this was written for a controlled, offline course lab environment to understand how buffer overflow exploits work at the byte level. It targets a specific practice binary from that assignment and isn't intended for use against real systems.
