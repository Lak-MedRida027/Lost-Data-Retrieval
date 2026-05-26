# 🔍 Lost Data Retrieval — JPEG File Carver

> **Cybersecurity Internship · Arch Technologies · Month 2 – Task 3**  
> A forensic data-recovery tool that scans raw drive sectors or disk images and retrieves deleted JPEG photographs using signature-based file carving techniques.

---

## 📌 What is File Carving?

File carving is a forensic data-recovery technique that reconstructs files from a raw byte stream — such as a disk image or an unallocated drive sector — by identifying file-type **magic bytes**, without relying on filesystem metadata structures (FAT tables, MFT records, or inodes).

Because it operates at the raw binary level, carving can recover files even after a format, deletion, or partial filesystem corruption.

---

## ✨ Features

| Feature | Description |
|---|---|
| **JFIF + EXIF support** | Detects both `FF D8 FF E0` and `FF D8 FF E1` headers |
| **Flexible source** | `--source` CLI flag accepts raw drives or disk image files |
| **Auto output dir** | `--output` flag; folder is created automatically if missing |
| **Dual-sink logging** | Real-time output to both `stdout` and a timestamped `.log` file |
| **Context managers** | All `open()` calls wrapped in `with` blocks — no file leaks |
| **Size sanity guards** | Min-size and max-size guards reject corrupt or partial fragments |
| **Error handling** | Catches `PermissionError`, `FileNotFoundError`, and `OSError` |
| **Zero dependencies** | Standard library only — no `pip install` required |

---

## 🔬 JPEG Magic Bytes

JPEG files use two well-known byte sequences as delimiters that make them ideal candidates for signature-based carving.

| Marker | Hex Bytes | Meaning |
|---|---|---|
| SOI (JFIF) | `FF D8 FF E0` | Start of Image — JFIF variant (web / camera) |
| SOI (EXIF) | `FF D8 FF E1` | Start of Image — EXIF variant (DSLR / phone) |
| EOI | `FF D9` | End of Image — present in every valid JPEG |

---

## 🏗️ Module Architecture

The tool is a single-file Python script with a clean four-layer structure.

```
main.py
├── CLI Layer          build_parser() / main()   — Argument parsing, output-dir creation, startup banner
├── Logging Layer      setup_logger()             — Dual-sink log: stdout + timestamped .log file
├── Carving Layer      carve()                    — Block-scan loop, header detection, footer search, I/O
└── Storage Layer      output_dir/                — Numbered .jpg files + recovery_*.log
```

**Requirements:** Python 3.10+ · No third-party libraries (`argparse`, `logging`, `sys`, `datetime`, `pathlib` only)

---

## ⚙️ Program Execution Flow

```
python main.py -s <SOURCE> -o <DIR>
        │
        ▼
Parse args → create output dir → init logger
        │
        ▼
open(source, "rb")  ← context manager
        │
        ▼
Read 512-byte block │ record fh.tell()
        │
     EOF? ──yes──► Recovery complete — print summary & exit
        │ no
        ▼
JFIF or EXIF header in block? (FF D8 FF E0/E1)
        │ no → continue outer loop
        │ yes
        ▼
Seek to jpeg_start → read chunks into buf
        │
     Found FF D9 (EOI)?  or  buf > 15 MB guard?
        │ no EOI / too big → log warning, skip fragment
        │ yes
        ▼
  len(buf) ≥ min_size?
        │ too small → log warning, skip fragment
        │ yes
        ▼
open(out_path, "wb") → write buf
Log filename + byte count → recovered += 1
Resume outer loop from fh.tell() (after EOI — no seek needed)
```

---

## 🚀 Installation & Usage

```bash
# 1. Clone the repository
git clone https://github.com/Lak-MedRida027/Lost-Data-Retrieval.git
cd Lost-Data-Retrieval

# 2. No dependencies to install — standard library only

# 3a. Run on a Windows raw drive (requires Administrator)
python main.py -s \\.\X: -o ./recovered

# 3b. Run on a Linux raw device (requires root)
sudo python main.py -s /dev/sdb -o ./recovered

# 3c. Run on a disk image file
python main.py -s disk.dd -o ./output --min-size 4096

# 4. View recovered files
ls ./recovered/*.jpg       # Linux / macOS
dir .\recovered\*.jpg      # Windows

# 5. View the recovery log
cat ./recovered/recovery_*.log    # Linux / macOS
type .\recovered\recovery_*.log   # Windows
```

### CLI Reference

```
usage: main.py [-h] -s SOURCE [-o OUTPUT] [--min-size MIN_SIZE]

options:
  -s, --source     Path to raw drive or disk image  (required)
  -o, --output     Output directory                 (default: ./recovered)
  --min-size       Minimum file size in bytes       (default: 1024)
```

---

## 📂 Output Structure

```
recovered/
├── recovered_0000.jpg
├── recovered_0001.jpg
├── recovered_0002.jpg
├── recovered_0003.jpg
└── recovery_20260525_021045.log
```

Each run produces a timestamped log file alongside the recovered images. Log entries include the exact byte offset where each header was found and the size of every saved file.

---

## 🛡️ Size Guards

Two guards protect against corrupt entries:

- **Min-size check** — fragments below 1 KB (default) are discarded. Deleted sectors often contain JPEG header remnants but only a few hundred bytes of actual data.
- **Max-size guard** — if the accumulation buffer exceeds 15 MB without an EOI footer, the search is abandoned. This prevents the tool from reading the entire drive into RAM when a footer byte has been overwritten.

---

## 🔭 Future Improvements

- **Multi-format support** — extend signature tables to recover PNG (`89 50 4E 47`), PDF (`25 50 44 46`), and MP4 files
- **Parallel carving** — split the source into chunks and carve with `multiprocessing.Pool` to saturate multi-core CPUs on large images
- **Hash deduplication** — compute SHA-256 of each recovered file and skip writing if an identical image was already saved
- **Metadata extraction** — use `Pillow` or `exiftool` to print EXIF fields (GPS coordinates, camera model, timestamp) alongside each recovered file in the log
- **GUI front-end** — wrap the carver in a simple `tkinter` or web interface for non-CLI users

---

## 🧠 Skills Demonstrated

- Digital forensics fundamentals: file carving and magic-byte analysis
- Low-level binary I/O and accurate file-pointer management in Python
- CLI tool design with `argparse` and structured dual-sink logging
- Defensive programming: context managers, size guards, exception handling
- JPEG file format internals: SOI/EOI markers, JFIF vs. EXIF distinction

---

## 👤 Author

**Mohammed Rida Lakhdari**  
Cybersecurity Engineering Student · Arch Technologies Intern  
📧 lakmedrida027@gmail.com  
🐙 [github.com/Lak-MedRida027](https://github.com/Lak-MedRida027)

---

> *Part of the Month 2 internship deliverables at Arch Technologies — Cybersecurity domain.*
