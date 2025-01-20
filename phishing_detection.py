import requests
from pytesseract import image_to_string
from pdf2image import convert_from_path

# VirusTotal API setup
API_KEY = "Add your VirusTotal API KEY"  # Replace with your API key
VT_URL = "https://www.virustotal.com/vtapi/v2/url/report"

# Function to analyze a URL using VirusTotal
def analyze_url(url):
    params = {'apikey': API_KEY, 'resource': url}
    response = requests.get(VT_URL, params=params)
    if response.status_code == 200:
        data = response.json()
        if data['response_code'] == 1:
            positives = data.get('positives', 0)
            total = data.get('total', 0)
            return f"URL: {url} - {positives}/{total} detections"
        else:
            return f"URL: {url} - No data available"
    else:
        return "Error querying VirusTotal API"

# Function to perform OCR and extract URLs
def extract_links_with_ocr(file_path):
    links = []
    try:
        images = convert_from_path(file_path)
        for image in images:
            text = image_to_string(image)
            print(f"OCR Text:\n{text}\n")  # Debug: Print OCR-extracted text
            # Extract URLs from the text
            words = text.split()
            links.extend([word for word in words if word.startswith("http") or word.startswith("www")])
    except Exception as e:
        print(f"Error during OCR: {e}")
    return links

# Main function to run the tool
def main():
    # PDF file path
    pdf_path = r"C:\Users\user\OneDrive\Documents\CYBERSECURITY PROJECTS\Phishing Detection\Sample_Email_Attachment.pdf"

    print(f"Analyzing PDF with OCR: {pdf_path}")
    links = extract_links_with_ocr(pdf_path)
    print(f"Extracted Links: {links}")

    # Analyze each extracted link
    for link in links:
        result = analyze_url(link)
        print(result)

if __name__ == "__main__":
    main()
