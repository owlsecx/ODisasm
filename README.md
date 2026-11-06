# 🦉 ODisasm

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Exploit%20/%20RE-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **ODisasm** — Multi-Arch Disassembler ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

ODisasm decodes x86, x64, ARM (A32) and AArch64 machine code from raw shellcode, hex strings, or ELF / PE / Mach-O executables (whose executable section, architecture, base and entry are detected automatically), using a linear sweep or recursive descent, and triages the result for shellcode traits (raw syscalls, GetPC, PEB walks, decoder loops, NOP sleds).

---

## ✨ Features

- Disassemble x86, x64, ARM (A32) and AArch64 from hex, raw bytes, ELF, PE or Mach-O
- Linear sweep or recursive-descent with CFG and basic-block leaders
- Auto-detect executable section, architecture, base and entry point
- Shellcode triage: raw syscalls, GetPC patterns and suspicious traits
- Opcode listing limits, section/offset/length slicing
- Export annotated listings via TXT/Markdown/JSON formats

---

## ⚙️ Requirements

- **Linux**
- **Go 1.21+** (stdlib only; `CGO_ENABLED=0`)

---

## 🚀 Usage

```bash
go build -ldflags="-s -w" -o ODisasm ODisasm.go
./ODisasm --help
./ODisasm --hex 4831c0c3 --arch x64
./ODisasm --input sample.bin --recursive --cfg
./ODisasm --input app.elf --section .text --limit 200
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad
