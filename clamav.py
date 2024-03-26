import requests

API_KEY = "336c64b97591aa90984a4e3788bd408080724ed6807c112be5f6fb6a71d125f8"
SCAN_URL = "https://www.virustotal.com/api/v3/files"

def scan_file(file_path):
    headers = {
        "x-apikey": API_KEY
    }

    with open(file_path, "rb") as file:
        file_data = file.read()

    response = requests.post(
        SCAN_URL,
        headers=headers,
        files={"file": (file_path, file_data)}
    )

    if response.status_code == 200:
        result = response.json()
        print(result)  
    else:
        print("Error:", response.status_code)

if __name__ == "__main__":
    file_path = r"C:\Users\Felix\OneDrive\Desktop\DSA 16M.txt"
    scan_file(file_path)
