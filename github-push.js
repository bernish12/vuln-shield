/**
 * VulnShield GitHub API Pusher
 * Uploads all project files to a new GitHub repository using the GitHub REST API.
 * No git install required — uses Node.js built-in https module.
 *
 * Usage:
 *   node github-push.js <GITHUB_TOKEN> <GITHUB_USERNAME>
 *
 * Get a token at: https://github.com/settings/tokens/new
 * Scopes needed: repo (full control of private repositories)
 */

const https = require('https');
const fs = require('fs');
const path = require('path');

const TOKEN = process.argv[2];
const USERNAME = process.argv[3];
const REPO_NAME = 'vuln-shield';

if (!TOKEN || !USERNAME) {
    console.error('Usage: node github-push.js <GITHUB_TOKEN> <GITHUB_USERNAME>');
    console.error('');
    console.error('Get a token at: https://github.com/settings/tokens/new');
    console.error('Required scopes: repo');
    process.exit(1);
}

// Files to upload (relative to project root)
const PROJECT_DIR = __dirname;
const EXCLUDE = [
    'node_modules', '.git', 'github-push.js',
    'PortableGit.exe'
];

function apiRequest(method, urlPath, body) {
    return new Promise((resolve, reject) => {
        const data = body ? JSON.stringify(body) : null;
        const options = {
            hostname: 'api.github.com',
            path: urlPath,
            method: method,
            headers: {
                'Authorization': `token ${TOKEN}`,
                'User-Agent': 'VulnShield-Deployer/1.0',
                'Content-Type': 'application/json',
                'Accept': 'application/vnd.github.v3+json',
            }
        };
        if (data) options.headers['Content-Length'] = Buffer.byteLength(data);

        const req = https.request(options, (res) => {
            let responseBody = '';
            res.on('data', chunk => responseBody += chunk);
            res.on('end', () => {
                try {
                    resolve({ status: res.statusCode, data: JSON.parse(responseBody) });
                } catch {
                    resolve({ status: res.statusCode, data: responseBody });
                }
            });
        });
        req.on('error', reject);
        if (data) req.write(data);
        req.end();
    });
}

function getFilesToUpload(dir, base = '') {
    const files = [];
    const items = fs.readdirSync(dir);
    for (const item of items) {
        if (EXCLUDE.includes(item)) continue;
        const fullPath = path.join(dir, item);
        const relativePath = base ? `${base}/${item}` : item;
        const stat = fs.statSync(fullPath);
        if (stat.isDirectory()) {
            files.push(...getFilesToUpload(fullPath, relativePath));
        } else {
            files.push({ fullPath, relativePath });
        }
    }
    return files;
}

async function main() {
    console.log(`\n🚀 VulnShield GitHub Deployer`);
    console.log(`   User: ${USERNAME}`);
    console.log(`   Repo: ${REPO_NAME}\n`);

    // Step 1: Create the repository
    console.log('📦 Creating GitHub repository...');
    const createResult = await apiRequest('POST', '/user/repos', {
        name: REPO_NAME,
        description: 'BernishVuln_Shield — Advanced Security Auditing & Vulnerability Scanner',
        private: false,
        auto_init: false
    });

    if (createResult.status === 201) {
        console.log(`✅ Repository created: ${createResult.data.html_url}`);
    } else if (createResult.status === 422) {
        console.log(`⚠️  Repository already exists — pushing files to existing repo.`);
    } else {
        console.error(`❌ Failed to create repo: ${createResult.status}`, createResult.data.message);
        process.exit(1);
    }

    // Step 2: Upload all files
    const files = getFilesToUpload(PROJECT_DIR);
    console.log(`\n📁 Found ${files.length} files to upload...\n`);

    let uploaded = 0;
    let failed = 0;

    for (const file of files) {
        const content = fs.readFileSync(file.fullPath);
        const base64Content = content.toString('base64');

        // Check if file already exists (get its SHA for update)
        let sha = null;
        const existing = await apiRequest('GET', `/repos/${USERNAME}/${REPO_NAME}/contents/${file.relativePath}`, null);
        if (existing.status === 200) {
            sha = existing.data.sha;
        }

        const uploadBody = {
            message: `Deploy: add ${file.relativePath}`,
            content: base64Content,
            branch: 'main'
        };
        if (sha) uploadBody.sha = sha;

        const result = await apiRequest('PUT', `/repos/${USERNAME}/${REPO_NAME}/contents/${file.relativePath}`, uploadBody);

        if (result.status === 201 || result.status === 200) {
            console.log(`  ✅ ${file.relativePath}`);
            uploaded++;
        } else {
            console.log(`  ❌ FAILED: ${file.relativePath} — ${result.data.message}`);
            failed++;
        }
    }

    console.log(`\n${'─'.repeat(50)}`);
    console.log(`✅ Uploaded: ${uploaded} files`);
    if (failed > 0) console.log(`❌ Failed:   ${failed} files`);
    console.log(`\n🌐 Repository URL: https://github.com/${USERNAME}/${REPO_NAME}`);
    console.log(`\n📋 Next step — Deploy on Render:`);
    console.log(`   1. Go to https://render.com`);
    console.log(`   2. Click "New +" → "Web Service"`);
    console.log(`   3. Connect GitHub → select "${REPO_NAME}"`);
    console.log(`   4. Settings:`);
    console.log(`      - Runtime: Node`);
    console.log(`      - Build Command: npm install`);
    console.log(`      - Start Command: node server.js`);
    console.log(`   5. Click "Create Web Service" → Done!`);
}

main().catch(console.error);
