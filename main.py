#!/usr/bin/env python3
"""
JPEG File Carver — Data Recovery Tool
======================================
Recovers JPEG images (JFIF and EXIF variants) from raw drives,
disk images, or any binary source by scanning for magic-byte
signatures and carving out complete image files.

Author  : Mohammed Rida Lakhdari
Org     : Arch Technologies — Cybersecurity Internship, Month 2 Task 1
Email   : lakmedrida027@gmail.com
"""

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path

# ── Constants ──────────────────────────────────────────────────────────────────
BLOCK_SIZE    = 512          # bytes per sector / read block
MIN_JPEG_SIZE = 1_024        # 1 KB  — skip suspiciously tiny / truncated files
MAX_JPEG_SIZE = 15_728_640   # 15 MB — bail-out guard when no footer is found

# Both JPEG variants share the same SOI marker (FF D8) but differ at byte 3:
#   FF E0 → JFIF (standard digital-camera / web JPEG)
#   FF E1 → EXIF (metadata-rich JPEG from modern cameras / phones)
JPEG_HEADERS: tuple[bytes, ...] = (
    b'\xff\xd8\xff\xe0',   # JFIF
    b'\xff\xd8\xff\xe1',   # EXIF
)
JPEG_FOOTER = b'\xff\xd9'  # EOI — End Of Image


# ── Logging setup ─────────────────────────────────────────────────────────────
def setup_logger(output_dir: Path) -> logging.Logger:
    """Configure a logger that writes to both stdout and a timestamped log file."""
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = output_dir / f"recovery_{ts}.log"
    fmt     = "%(asctime)s  [%(levelname)-8s]  %(message)s"

    logging.basicConfig(
        level=logging.INFO,
        format=fmt,
        handlers=[
            logging.FileHandler(log_path, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )
    return logging.getLogger("jpeg_carver")


# ── Core carving logic ────────────────────────────────────────────────────────
def carve(
    source: str,
    output_dir: Path,
    min_size: int,
    logger: logging.Logger,
) -> int:
    """
    Scan *source* block-by-block, detect JPEG headers, extract each image
    up to its EOI footer, and write it to *output_dir*.

    Returns the number of successfully recovered files.

    Bug-fix note
    ------------
    The original script tracked position via a manual `offs` counter that was
    never updated during the inner read loop.  After the inner loop it called
    ``fileD.seek((offs+1)*size)``, which always seeked back to just after the
    *header block* rather than to the byte after the recovered image's footer.
    This caused every carve to re-scan already-processed data and produced
    duplicate / truncated output files.

    Fix: we use ``fh.tell()`` exclusively to track the file-pointer position.
    After carving a JPEG the pointer sits at (footer_offset + 2), which is
    exactly the right place to resume scanning — no extra seek needed.
    """
    recovered = 0

    try:
        with open(source, "rb") as fh:   # context manager — no handle leaks
            while True:
                block_start = fh.tell()
                block = fh.read(BLOCK_SIZE)
                if not block:
                    break  # clean EOF

                # ── Search this block for either JPEG variant ─────────────────
                best_pos   = -1
                best_label = ""

                for hdr in JPEG_HEADERS:
                    pos = block.find(hdr)
                    if pos != -1 and (best_pos == -1 or pos < best_pos):
                        best_pos   = pos
                        best_label = "JFIF" if hdr == JPEG_HEADERS[0] else "EXIF"

                if best_pos == -1:
                    continue  # no header in this block — advance

                jpeg_start = block_start + best_pos
                logger.info(f"Found {best_label} header @ offset {hex(jpeg_start)}")

                # ── Seek to the exact start of the JPEG data ──────────────────
                fh.seek(jpeg_start)

                # ── Read forward until EOI footer ─────────────────────────────
                buf       = bytearray()
                found_eoi = False

                while True:
                    chunk = fh.read(BLOCK_SIZE)
                    if not chunk:
                        break  # source exhausted before footer
                    eoi = chunk.find(JPEG_FOOTER)
                    if eoi != -1:
                        buf.extend(chunk[: eoi + 2])  # include the 2-byte footer
                        found_eoi = True
                        break
                    buf.extend(chunk)
                    if len(buf) > MAX_JPEG_SIZE:
                        logger.warning(
                            f"  ↳ No footer after {MAX_JPEG_SIZE // 1_048_576} MB "
                            "— file likely corrupt, skipping"
                        )
                        break

                if not found_eoi:
                    # Skip past this bad header and keep scanning
                    fh.seek(jpeg_start + len(JPEG_HEADERS[0]))
                    continue

                # ── Sanity check: reject suspiciously small files ─────────────
                if len(buf) < min_size:
                    logger.warning(
                        f"  ↳ File only {len(buf)} bytes (min {min_size}) — skipping"
                    )
                    # fh already sits after the footer; resume scanning from there
                    continue

                # ── Write to output directory ─────────────────────────────────
                out_path = output_dir / f"recovered_{recovered:04d}.jpg"
                try:
                    with open(out_path, "wb") as wh:
                        wh.write(buf)
                    logger.info(
                        f"  ↳ Saved: {out_path.name}  "
                        f"({len(buf):,} bytes)"
                    )
                    recovered += 1
                except OSError as exc:
                    logger.error(f"  ↳ Write failed: {exc}")

                # fh.tell() is already positioned right after the EOI footer.
                # The outer while-loop will call fh.read(BLOCK_SIZE) from here —
                # no manual seek required (this was the original bug).

    except PermissionError:
        logger.error(
            f"Permission denied: '{source}'\n"
            "  → Run as Administrator (Windows) or root (Linux) for raw drives."
        )
        sys.exit(1)
    except FileNotFoundError:
        logger.error(f"Source not found: '{source}'")
        sys.exit(1)
    except OSError as exc:
        logger.error(f"I/O error on '{source}': {exc}")
        sys.exit(1)

    return recovered


# ── Argument parser ───────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="jpeg_carver",
        description=(
            "JPEG File Carver — recovers JFIF/EXIF images from raw drives "
            "or disk image files by scanning for magic-byte signatures."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=r"""
Examples
--------
  # Windows — carve raw drive X:
  python main.py -s \\.\X: -o ./recovered

  # Linux — carve raw device
  python main.py -s /dev/sdb -o ./recovered

  # Disk image (.dd / .img) with custom minimum size
  python main.py -s disk.dd -o ./output --min-size 4096
""",
    )
    p.add_argument(
        "-s", "--source",
        required=True,
        metavar="SOURCE",
        help="Raw drive path (e.g. \\\\.\\X: or /dev/sdb) or disk image file",
    )
    p.add_argument(
        "-o", "--output",
        default="./recovered",
        metavar="DIR",
        help="Output directory for recovered files (created if absent, default: ./recovered)",
    )
    p.add_argument(
        "--min-size",
        type=int,
        default=MIN_JPEG_SIZE,
        metavar="BYTES",
        help=f"Minimum file size in bytes — smaller files are skipped (default: {MIN_JPEG_SIZE})",
    )
    return p


# ── Entry point ───────────────────────────────────────────────────────────────
def main() -> None:
    args    = build_parser().parse_args()
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    log = setup_logger(out_dir)
    SEP = "─" * 62

    log.info(SEP)
    log.info("JPEG File Carver  |  Arch Technologies Cybersecurity Internship")
    log.info(f"Source   : {args.source}")
    log.info(f"Output   : {out_dir.resolve()}")
    log.info(f"Min size : {args.min_size:,} bytes")
    log.info(f"Max size : {MAX_JPEG_SIZE // 1_048_576} MB  (corrupt-file guard)")
    log.info(SEP)

    count = carve(args.source, out_dir, args.min_size, log)

    log.info(SEP)
    if count:
        log.info(f"✔  Recovery complete — {count} file(s) saved to {out_dir.resolve()}")
    else:
        log.info("✘  Recovery complete — no JPEG files found in the source.")
    log.info(SEP)


if __name__ == "__main__":
    main()
