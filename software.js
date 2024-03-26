const { execSync } = require('child_process');

function getInstalledSoftware() {
    if (platform.system() === "Windows") {
        const command = 'wmic product get name, version';
        const output = execSync(command, { encoding: 'utf-8' });
        return output;
    } else {
        return "Unsupported operating system";
    }
}
function run(){
    const installedSoftware = getInstalledSoftware();
    console.log(installedSoftware);
}
