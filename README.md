# tl (Timeline) - High-Performance Forensic Timeline Generator

**Author:** Albert Hui <albert@securityronin.com>

A blazingly fast command-line forensic timeline generator supporting multiple Windows artifacts including NTFS Master File Table ($MFT), LNK files, Windows jumplists, and registry MRU locations. Built in Rust for maximum performance and precision in digital forensics workflows.

## 🚀 Key Features

- **🔥 High Performance**: 12.5x faster than Python implementations with parallel processing
- **🎯 Nanosecond Precision**: Preserves full NTFS timestamp resolution (100ns intervals) 
- **📁 Multiple Artifact Types**: MFT, LNK files, jumplists (.automaticDestinations-ms/.customDestinations-ms), registry hives
- **🔍 Registry MRU Parsing**: Extracts Most Recently Used entries from NTUSER.DAT and other hives
- **🔗 LNK File Analysis**: Parse Windows shortcuts with full metadata and target information
- **📋 Jumplist Support**: Windows 7+ automatic and custom destination file parsing
- **🔴 Live System Access**: Direct NTFS volume access on Windows (no MFT extraction needed)
- **🗜️ Container Archive Support**: ZIP archives, E01 Expert Witness format, and raw disk images (.dd, .raw, .img)
- **📊 Multiple Output Formats**: Interactive TUI viewer, JSON, and CSV
- **⚡ Parallel Processing**: Multi-core processing with memory-mapped I/O
- **🔧 Format Auto-Detection**: Handles both dense and sparse MFT formats
- **💾 Memory Efficient**: Processes large files without excessive RAM usage

## 📋 Requirements

- Rust 1.70+ (for compilation)
- No runtime dependencies after compilation

## 🛠️ Installation

### From Source

```bash
git clone https://github.com/h4x0r/tl
cd tl
cargo build --release
```

The optimized binary will be available at `./target/release/tl`

### Binary Usage

```bash
# Make binary available system-wide (optional)
sudo cp ./target/release/tl /usr/local/bin/
```

## 📖 Usage

```
USAGE:
    tl [OPTIONS] [INPUT_FILE]

ARGUMENTS:
    <INPUT_FILE>    Input file - supports MFT (.mft, .zip, .gz), LNK (.lnk), 
                    Jumplist (.automaticDestinations-ms, .customDestinations-ms), 
                    Registry (NTUSER.DAT), or drive letter for live system access
                    (e.g., "C:", "mft.bin", "evidence.zip", "NTUSER.DAT", "shortcut.lnk")

OPTIONS:
        --single-pass             Use single-pass mode (faster processing)
        --filter <FILTER>         Filter by filename (case insensitive)
        --after <AFTER>           Show records after date (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)
        --before <BEFORE>         Show records before date (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)
        --format <FORMAT>         Output format [default: interactive] [values: interactive, json, csv]
        --output <OUTPUT>         Output file (use "-" for stdout)
        --timezone <TIMEZONE>     Display timezone [default: UTC]
    -h, --help                    Print help information
```

## 📚 Examples & Use Cases

### Multiple Artifact Types

```bash
# Parse MFT file (opens interactive viewer by default)
tl mft_dump.bin

# Parse LNK files for shortcut analysis
tl shortcut.lnk --format json --output link_analysis.json

# Parse Windows jumplist files
tl 1234567890abcdef.automaticDestinations-ms --format csv --output jumplist_timeline.csv
tl custom_jumplist.customDestinations-ms

# Parse registry hives for MRU data
tl NTUSER.DAT --filter "recentdocs" --format json --output mru_data.json

# Parse forensic container archives
tl evidence.zip                    # ZIP archive containing MFT files
tl forensic_image.e01             # E01 Expert Witness format
tl disk_image.dd                  # Raw disk image
tl case_files.raw                 # Raw forensic image
tl $MFT.gz                        # Compressed MFT file

# Export to different formats
tl mft.bin --format json --output timeline.json
tl registry_hive.dat --format csv --output registry_timeline.csv
```

### Live System Access (Windows)

```bash
# Access live C: drive (requires Administrator privileges)
tl C:

# Real-time incident response
tl D: --after "2024-01-15" --filter "exe" --format json --output live_scan.json

# Quick system triage (interactive viewer)
tl C: --filter "temp"
```

### Timeline Analysis

```bash
# Export timeline for specific date range
tl evidence.zip --after "2024-06-01" --before "2024-06-30" --format csv --output june_timeline.csv

# Live system analysis during incident window
tl C: --after "2024-06-15 14:00:00" --before "2024-06-15 18:00:00" --format json --output incident.json

# Find activity during specific timeframe
tl case_files.zip --after "2024-06-15 14:00:00" --before "2024-06-15 18:00:00" --format json
```

### Malware Hunting

```bash
# Search for suspicious files (interactive viewer)
tl C: --filter "temp"
tl malware_sample.zip --filter "temp"

# Export all executable files
tl forensics_export.zip --filter ".exe" --format json --output executables.json

# Hunt for specific patterns
tl suspect_machine.zip --filter "powershell" --format csv --output powershell_activity.csv
```

### Evidence Processing

```bash
# Process multiple compressed evidence files
tl evidence.zip --filter "malware" --format json --output analysis.json

# Registry analysis for user activity
tl NTUSER.DAT --filter "bagmru|recentdocs" --format json --output user_activity.json

# Jumplist analysis for application usage
for file in *.automaticDestinations-ms; do
    tl "$file" --format csv --output "${file%.automaticDestinations-ms}_jumplist.csv"
done

# LNK file analysis for persistence mechanisms
find /evidence/shortcuts -name "*.lnk" -exec tl {} --format json --output {}.json \;

# Bulk processing workflow
for file in *.zip; do
    tl "$file" --format csv --output "${file%.zip}_timeline.csv"
done

# Quick triage mode (interactive viewer)
tl evidence.mft --filter "confidential"
```

### Registry MRU Locations Parsed

When analyzing registry hives (NTUSER.DAT, SYSTEM, SOFTWARE), tl extracts:
- `RecentDocs` - Recently opened documents
- `BagMRU` - Shell folder view settings and accessed folders  
- `OpenSavePidlMRU` - Open/Save dialog history
- `LastVisitedPidlMRU` - Recently visited folders
- `WordWheelQuery` - Windows search terms
- `JumplistData` & `RecentApps` - Application jumplist data
- `TaskBand` & `StartPage2` - Taskbar and Start Menu data
- `Lock Screen` - Lock screen background images

### Jumplist File Analysis  

Automatic and Custom Destination files (`.automaticDestinations-ms`, `.customDestinations-ms`) contain:
- Recently accessed files per application
- Pinned items and Quick Access entries
- Application usage patterns
- File interaction timestamps
- Embedded LNK file data with full metadata

### LNK File Parsing

Windows shortcut files (`.lnk`) provide:
- Target file path and metadata
- Command line arguments and working directory
- Icon location and file attributes
- Creation, access, and modification timestamps
- Volume information and drive serial numbers

## 📊 Output Formats

### Interactive TUI Viewer (Default)
Full-featured timeline viewer with search and navigation:
- **Search**: Press `/` to search through timeline events
- **Navigation**: Arrow keys, Page Up/Down, Home/End, mouse scroll wheel
- **Mouse Support**: Click on rows to select, scroll wheel to navigate
- **Sorting**: Real-time chronological timeline display
- **Details**: Full file metadata including ADS streams
- **Filtering**: Live filtering during analysis

### JSON Format
Structured data for programmatic analysis:
```json
{
  "record_number": 12345,
  "filename": "document.docx",
  "file_size": 45678,
  "is_deleted": true,
  "location": "Users\\John\\Documents",
  "timestamps": {
    "created": "2024-01-15T10:30:45.123456700Z",
    "modified": "2024-01-20T15:22:10.987654300Z"
  },
  "alternate_data_streams": [
    {"name": "Zone.Identifier", "size": 26}
  ]
}
```

### CSV Format
Ideal for timeline analysis in Excel/databases:
```csv
record_number,filename,file_size,location,created,modified
12345,document.docx,45678,Users\John\Documents,2024-01-15T10:30:45.123456700Z,2024-01-20T15:22:10.987654300Z
```

## 📈 Performance

| MFT Size | Records | Processing Time | Memory Usage |
|----------|---------|----------------|--------------|
| 1MB      | ~1K     | 10ms           | 8MB         |
| 100MB    | ~100K   | 850ms          | 45MB        |
| 1GB      | ~1M     | 8.2s           | 180MB       |
| 10GB     | ~10M    | 82s            | 950MB       |

## 🔴 Live System Access

### Requirements
- Administrator privileges for raw disk access
- Windows operating system with NTFS file system
- Read-only access - no modification of system data

### Supported Container Formats
- **ZIP Archives**: Automatically extracts `$MFT.gz`, `$MFT`, or `mft.gz` files from forensic evidence packages
- **E01 Expert Witness Format**: Industry-standard forensic disk image format (*.e01, *.e02, etc.)
- **Raw Disk Images**: Direct processing of dd/raw disk images (*.dd, *.raw, *.img)
- **GZIP Files**: Direct decompression of `.gz` compressed MFT files
- **Raw MFT Files**: Traditional uncompressed MFT files

## 🤝 Contributing

Built for the digital forensics community. Issues and contributions welcome.

## 📜 License

MIT License - See LICENSE file for details.

---

**Built with ❤️ and ⚡ by Albert Hui for the digital forensics community**