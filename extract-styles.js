const fs = require('fs');

function extractStyles(fileName, newStyleName) {
    let content = fs.readFileSync(fileName, 'utf8');
    const styleMatch = content.match(/<style>([\s\S]*?)<\/style>/);
    if (styleMatch) {
        fs.writeFileSync(newStyleName, styleMatch[1].trim());
        content = content.replace(styleMatch[0], '<link rel="stylesheet" href="' + newStyleName + '">');
        
        // Also remove any inline style="" attributes
        content = content.replace(/ style="[^"]*"/g, '');
        
        fs.writeFileSync(fileName, content);
        console.log(fileName + ' styles extracted to ' + newStyleName);
    }
}

extractStyles('analytics.html', 'analytics.css');
extractStyles('login.html', 'login.css');
extractStyles('index.html', 'index-inline.css');
extractStyles('404.html', '404.css');
