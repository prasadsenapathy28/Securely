import winreg

def get_installed_software():
    installed_software = []
    
    reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
    
    try:
        i = 0
        while True:
            subkey_name = winreg.EnumKey(reg_key, i)
            subkey_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" + "\\" + subkey_name
            
            try:
                subkey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey_path)
                software_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                installed_software.append(software_name)
                
                winreg.CloseKey(subkey)
            except FileNotFoundError:
                pass
            
            i += 1
    except OSError:
        pass
    
    winreg.CloseKey(reg_key)
    
    return installed_software

def get_latest_patch(software_name):
    latest_patch_version = "X.X.X"
    
    return latest_patch_version

def compare_patch_status(software_list):
    for software in software_list:
        print(f"Checking patch status for {software}...")        
        latest_patch_version = get_latest_patch(software) 
        print(f"{software} is up to date.")
        

installed_software = get_installed_software()

compare_patch_status(installed_software)
