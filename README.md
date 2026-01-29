# LogParsers

LogParsers is a Python-based repository for creating and testing parsers for
different types of SDV (Software-Defined Vehicle) logs.

Each log type is organized into its own folder, while all parsers share a
common set of dependencies defined in a single `requirements.txt`.

## Supported Log Types

- **DLT logs**
- **PCAP files**
- **Coredumps**

## Repository Structure

```

LogParsers/
├── parsers/
│   ├── dlt/        # DLT log parsers
│   ├── pcap/       # PCAP log parsers
│   └── coredumps/  # Coredump parsers
├── requirements.txt
├── .gitignore
└── README.md

````

## Setup

It is recommended to use a virtual environment.

```bash
python -m venv parservenv
source parservenv/bin/activate   # Linux / macOS
parservenv\Scripts\activate      # Windows
````

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Each parser can be developed and tested independently within its respective
folder. Shared utilities or common logic can be added later if required.

## Notes

* Large log files (e.g., `.pcap`, `.log`, core dumps) are excluded via
  `.gitignore`.
* This repository is intended for experimentation, prototyping, and parser
  development.


