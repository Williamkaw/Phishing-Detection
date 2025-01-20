# Phishing Detection Tool

A Python-based tool to analyze PDFs for suspicious links using OCR and VirusTotal.

## Features
- Extracts plain-text and embedded links from PDFs.
- Performs OCR on scanned PDFs to detect URLs.
- Queries VirusTotal to check if URLs are malicious.

## Requirements
- Python 3.x
- Libraries: `pytesseract`, `pdf2image`, `requests`, `pdfplumber`

## Usage
1. Set up your VirusTotal API key in the script.
2. Run the script with a target PDF.

## License
MIT
