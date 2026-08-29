const fs = require('fs');

function extractScript(fileName, newScriptName) {
    const content = fs.readFileSync(fileName, 'utf8');
    const scriptMatch = content.match(/<script>([\s\S]*?)<\/script>/);
    if (scriptMatch) {
        fs.writeFileSync(newScriptName, scriptMatch[1].trim());
        fs.writeFileSync(fileName, content.replace(scriptMatch[0], '<script src="' + newScriptName + '"></script>'));
        console.log(fileName + ' script extracted');
    }
}

extractScript('analytics.html', 'analytics-script.js');
extractScript('404.html', '404-script.js');
