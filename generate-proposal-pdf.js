const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');

function createProposalPDF(outputPath) {
    const doc = new PDFDocument({
        margin: 40,
        size: 'A4',
        bufferPages: true
    });

    const writeStream = fs.createWriteStream(outputPath);
    doc.pipe(writeStream);

    // Color Palette
    const COLORS = {
        primary: '#0d1117',
        accent: '#00f2fe',
        accentDark: '#4facfe',
        textDark: '#1e293b',
        textMuted: '#64748b',
        bgLight: '#f8fafc',
        cardBg: '#f1f5f9',
        border: '#e2e8f0',
        success: '#10b981',
        warning: '#f59e0b',
        danger: '#ef4444',
        white: '#ffffff'
    };

    // --- PAGE 1: HEADER & COVER BANNER ---
    doc.rect(0, 0, doc.page.width, 140).fill(COLORS.primary);

    // Cyber Shield Icon Graphic / Logo
    doc.fillColor(COLORS.accent)
       .fontSize(28)
       .font('Helvetica-Bold')
       .text('BERNISH VULN_SHIELD', 40, 40);

    doc.fillColor('#94a3b8')
       .fontSize(12)
       .font('Helvetica')
       .text('Advanced Security Auditing & Vulnerability Management Platform', 40, 75);

    doc.fillColor(COLORS.accentDark)
       .fontSize(10)
       .font('Helvetica-Bold')
       .text('LIVE DEMO: https://vuln-shield-k5fw.onrender.com', 40, 98);

    doc.y = 160;

    // Document Title Banner
    doc.fillColor(COLORS.textDark)
       .fontSize(20)
       .font('Helvetica-Bold')
       .text('CLIENT SALES PROPOSAL & PRODUCT PITCH', 40, 160);

    doc.strokeColor(COLORS.accent)
       .lineWidth(3)
       .moveTo(40, 188)
       .lineTo(250, 188)
       .stroke();

    doc.y = 205;

    // --- EXECUTIVE SUMMARY BOX ---
    doc.rect(40, doc.y, doc.page.width - 80, 85)
       .fillAndStroke(COLORS.cardBg, COLORS.border);

    doc.fillColor(COLORS.primary)
       .fontSize(12)
       .font('Helvetica-Bold')
       .text('📌 Executive Summary', 55, 218);

    doc.fillColor(COLORS.textDark)
       .fontSize(9.5)
       .font('Helvetica')
       .text(
           'Bernish VulnShield is an all-in-one automated cybersecurity auditing platform that enables IT agencies, enterprises, and consultants to continuously scan websites, mobile applications, and source code for OWASP Top 10 vulnerabilities, leaked API keys, and security misconfigurations in under 60 seconds.',
           55,
           238,
           { width: doc.page.width - 110, align: 'justify', lineGap: 3 }
       );

    doc.y = 310;

    // --- KEY MODULES & FEATURES SECTION ---
    doc.fillColor(COLORS.primary)
       .fontSize(14)
       .font('Helvetica-Bold')
       .text('🌟 Core Product Modules & Capabilities', 40, doc.y);

    let moduleY = doc.y + 25;

    const modules = [
        {
            title: '1. Web Vulnerability & OWASP Top 10 Scanner',
            desc: 'Automated header auditing (CSP, HSTS, X-Frame), XSS & SQLi risk detection, SSL/TLS certificate validity checks, and CORS misconfiguration scanning.'
        },
        {
            title: '2. Mobile App & Source Code Auditor',
            desc: 'Parses AndroidManifest.xml for insecure permissions and scans codebases for exposed AWS, Stripe, Google API keys, and hardcoded secrets.'
        },
        {
            title: '3. Device & Infrastructure Compliance Audit',
            desc: 'Evaluates local system security, OS patch compliance, open listening ports, firewall configurations, and network risk exposure.'
        },
        {
            title: '4. Executive PDF & HTML Audit Report Generator',
            desc: 'Generates one-click white-label PDF/HTML reports complete with executive security scores (0-100%) and actionable code remediation snippets.'
        },
        {
            title: '5. Admin Intelligence & Visitor Audit Trail',
            desc: 'Tracks admin logins, IP addresses, geolocation data, and maintains active visitor audit logs for full compliance traceability.'
        }
    ];

    modules.forEach((mod) => {
        doc.rect(40, moduleY, doc.page.width - 80, 48)
           .fillAndStroke(COLORS.bgLight, COLORS.border);

        doc.fillColor(COLORS.primary)
           .fontSize(10)
           .font('Helvetica-Bold')
           .text(mod.title, 52, moduleY + 8);

        doc.fillColor(COLORS.textMuted)
           .fontSize(8.5)
           .font('Helvetica')
           .text(mod.desc, 52, moduleY + 22, { width: doc.page.width - 104, lineGap: 2 });

        moduleY += 56;
    });

    // --- PAGE 2: COMMERCIAL PRICING & INVESTMENT ---
    doc.addPage();

    doc.fillColor(COLORS.primary)
       .fontSize(16)
       .font('Helvetica-Bold')
       .text('💎 Commercial Pricing Packages & Investment Options', 40, 40);

    doc.strokeColor(COLORS.accent)
       .lineWidth(3)
       .moveTo(40, 62)
       .lineTo(200, 62)
       .stroke();

    let tableTop = 80;
    const colWidths = [120, 135, 135, 125];
    const headers = ['Package / Tier', 'Target Client', 'Key Deliverables', 'One-Time Investment'];

    // Draw Table Header
    doc.rect(40, tableTop, doc.page.width - 80, 25).fill(COLORS.primary);
    let xOffset = 45;
    headers.forEach((h, idx) => {
        doc.fillColor(COLORS.white)
           .fontSize(9)
           .font('Helvetica-Bold')
           .text(h, xOffset, tableTop + 8);
        xOffset += colWidths[idx];
    });

    // Table Rows
    const packages = [
        {
            name: 'Package 1:\nBasic License',
            target: 'Freelancers & Small Agencies',
            details: 'Self-hosted license\nUnlimited Web Scans\nStandard PDF Export\n1 Month Bug Fixes',
            price: '₹25,000 INR\n($300 USD)'
        },
        {
            name: 'Package 2:\nPro Managed\n(Recommended)',
            target: 'IT Companies &\nSecurity Auditors',
            details: 'Fully Managed Cloud\nWeb, App & Device Scans\nBranded PDF Reports\n6 Months Support',
            price: '₹55,000 INR\n($680 USD)'
        },
        {
            name: 'Package 3:\nWhite-Label SaaS',
            target: 'Enterprise Buyers &\nSaaS Providers',
            details: 'Multi-tenant SaaS Engine\nCustom Logo & Domain\nFull White-Labeling\n1 Year Priority Support',
            price: '₹1,10,000 INR\n($1,350 USD)'
        }
    ];

    let rowY = tableTop + 25;
    packages.forEach((pkg, rIdx) => {
        const rowHeight = 70;
        const bg = rIdx % 2 === 0 ? COLORS.bgLight : COLORS.white;

        doc.rect(40, rowY, doc.page.width - 80, rowHeight).fillAndStroke(bg, COLORS.border);

        // Col 1: Name
        doc.fillColor(COLORS.primary)
           .fontSize(9)
           .font('Helvetica-Bold')
           .text(pkg.name, 45, rowY + 12);

        // Col 2: Target
        doc.fillColor(COLORS.textDark)
           .fontSize(8.5)
           .font('Helvetica')
           .text(pkg.target, 45 + colWidths[0], rowY + 12);

        // Col 3: Details
        doc.fillColor(COLORS.textMuted)
           .fontSize(8)
           .font('Helvetica')
           .text(pkg.details, 45 + colWidths[0] + colWidths[1], rowY + 10, { lineGap: 2 });

        // Col 4: Price
        doc.fillColor(COLORS.success)
           .fontSize(10)
           .font('Helvetica-Bold')
           .text(pkg.price, 45 + colWidths[0] + colWidths[1] + colWidths[2], rowY + 12);

        rowY += rowHeight;
    });

    // --- CLIENT PITCH DECK GUIDE (SLIDE BREAKDOWN) ---
    doc.y = rowY + 25;
    doc.fillColor(COLORS.primary)
       .fontSize(14)
       .font('Helvetica-Bold')
       .text('🗣️ Client Sales Pitch Deck (Talking Points Guide)', 40, doc.y);

    let pitchY = doc.y + 20;

    const slides = [
        {
            title: 'Slide 1: The Problem',
            eng: 'Most companies do not realize their app has security flaws until hackers exploit them. Manual audits cost upwards of $2,000.',
            tan: 'Machi, neraiya company-ku unga website la XSS / secret leak aagirukku nu hack aaguravara theriyadhu. Audit cost thaan adhigam.'
        },
        {
            title: 'Slide 2: The Solution (VulnShield)',
            eng: 'Bernish VulnShield automates vulnerability scanning in 60 seconds, delivering instant security scores and exact code fixes.',
            tan: 'VulnShield ore click la 60 seconds kula ungalla website & mobile app full security-a audit panni PDF report kuduthudum.'
        },
        {
            title: 'Slide 3: ROI & Business Savings',
            eng: 'Saves 100+ dev hours per audit and protects against compliance fines up to $50,000.',
            tan: 'Client dev team-ode 100+ hours time save aagum, data breach fines-la irundhu thapikkalam.'
        }
    ];

    slides.forEach((slide) => {
        doc.rect(40, pitchY, doc.page.width - 80, 52).fillAndStroke(COLORS.cardBg, COLORS.border);

        doc.fillColor(COLORS.primary)
           .fontSize(9.5)
           .font('Helvetica-Bold')
           .text(slide.title, 50, pitchY + 6);

        doc.fillColor(COLORS.textDark)
           .fontSize(8)
           .font('Helvetica')
           .text(`• English Pitch: ${slide.eng}`, 50, pitchY + 20, { width: doc.page.width - 100 });

        doc.fillColor(COLORS.accentDark)
           .fontSize(8)
           .font('Helvetica-Oblique')
           .text(`• Tanglish Pitch: "${slide.tan}"`, 50, pitchY + 34, { width: doc.page.width - 100 });

        pitchY += 58;
    });

    // --- FOOTER SETUP ON ALL PAGES ---
    const pages = doc.bufferedPageRange();
    for (let i = 0; i < pages.count; i++) {
        doc.switchToPage(i);

        // Footer Bar
        doc.strokeColor(COLORS.border)
           .lineWidth(1)
           .moveTo(40, doc.page.height - 40)
           .lineTo(doc.page.width - 40, doc.page.height - 40)
           .stroke();

        doc.fillColor(COLORS.textMuted)
           .fontSize(8)
           .font('Helvetica')
           .text('Bernish VulnShield — Commercial Sales Proposal & Product Overview', 40, doc.page.height - 30);

        doc.fillColor(COLORS.textMuted)
           .fontSize(8)
           .font('Helvetica')
           .text(`Page ${i + 1} of ${pages.count}`, doc.page.width - 100, doc.page.height - 30, { align: 'right' });
    }

    doc.end();
    return writeStream;
}

const workspaceOutput = path.join(__dirname, 'Bernish_VulnShield_Sales_Proposal.pdf');
const brainOutput = path.join('C:\\Users\\P52\\.gemini\\antigravity-ide\\brain\\75f9c46b-ff4d-404f-8645-29764a2f33f3', 'Bernish_VulnShield_Sales_Proposal.pdf');

console.log('Generating workspace PDF...');
createProposalPDF(workspaceOutput);

console.log('Generating artifacts PDF...');
createProposalPDF(brainOutput);

console.log('PDF Generation initiated successfully!');
