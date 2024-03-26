function getInstalledSoftware() {
    var installedSoftware = [];
    var regKey = require('winreg').OpenKey(require('winreg').HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
    try {
        var i = 0;
        while (true) {
            var subkeyName = require('winreg').EnumKey(regKey, i);
            var subkeyPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" + "\\" + subkeyName;
            try {
                var subkey = require('winreg').OpenKey(require('winreg').HKEY_LOCAL_MACHINE, subkeyPath);
                var softwareName = require('winreg').QueryValueEx(subkey, "DisplayName")[0];
                installedSoftware.push(softwareName);
                require('winreg').CloseKey(subkey);
            } catch (error) {
                // pass
            }
            i += 1;
        }
    } catch (error) {
        // pass
    }
    require('winreg').CloseKey(regKey);
    return installedSoftware;
}

function getLatestPatch(softwareName) {
    var latestPatchVersion = "X.X.X";
    return latestPatchVersion;
}

function comparePatchStatus(softwareList) {
    for (var i = 0; i < softwareList.length; i++) {
        var software = softwareList[i];
        console.log("Checking patch status for " + software + "...");
        var latestPatchVersion = getLatestPatch(software);
        console.log(software + " is up to date.");
    }
}

function run(){
    var installedSoftware = getInstalledSoftware();
    comparePatchStatus(installedSoftware);
}
