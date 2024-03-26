import os
# from WindowsDefender import Windowsdefender;

def scan_file(file_path):
    defender = WindowsDefender()

    # Scan the file
    result = defender.scan(file_path)

    # Check the scan result
    if result.is_infected:
        print("File is infected:", result.name)
        print("Threat detected:", result.threat)
    else:
        print("File is clean")

def examine_files(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            print(file_path)


root_directory = '/'

examine_files(root_directory)
