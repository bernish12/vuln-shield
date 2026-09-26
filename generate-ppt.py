from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
import os

# Create a new presentation
prs = Presentation()

# Set slide width and height for 16:9 widescreen
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)

# Function to apply a dark theme to a slide background
def apply_dark_theme(slide):
    background = slide.background
    fill = background.fill
    fill.solid()
    fill.fore_color.rgb = RGBColor(10, 25, 47) # Dark blue/black cyber background

# Function to format text
def format_text(shape, font_size=28, is_bold=False, color=RGBColor(204, 214, 246)):
    for paragraph in shape.text_frame.paragraphs:
        for run in paragraph.runs:
            run.font.size = Pt(font_size)
            run.font.bold = is_bold
            run.font.color.rgb = color
            run.font.name = 'Arial'

# Function to format title
def format_title(shape):
    shape.text_frame.paragraphs[0].runs[0].font.size = Pt(44)
    shape.text_frame.paragraphs[0].runs[0].font.bold = True
    shape.text_frame.paragraphs[0].runs[0].font.color.rgb = RGBColor(10, 255, 137) # Hacker green
    shape.text_frame.paragraphs[0].runs[0].font.name = 'Arial'

# Slide 1: Title
slide_layout = prs.slide_layouts[0] # Title slide layout
slide = prs.slides.add_slide(slide_layout)
apply_dark_theme(slide)
title = slide.shapes.title
subtitle = slide.placeholders[1]
title.text = "VULN-SHIELD: Next-Gen Cyber Defense"
subtitle.text = "Spectra 2026 Paper Presentation\nCyber Security and Digital Technology\nPresented by: Bernish12"
format_title(title)
format_text(subtitle, 24, False, RGBColor(168, 178, 209))
slide.notes_slide.notes_text_frame.text = "Good morning respected judges. My name is Bernish, and today I am presenting my research and working prototype on a unified cybersecurity system called Vuln-Shield."

# Slide Content Data
slides_data = [
    {
        "title": "The Fragmentation of Modern Security",
        "bullets": [
            "Cyber attacks target multiple vectors simultaneously.",
            "Current tools only scan one layer at a time (network OR local OS).",
            "Small enterprises lack the budget for 360° protection suites.",
            "Result: Blind spots lead to catastrophic data breaches."
        ],
        "notes": "The biggest problem in cybersecurity today is fragmentation. Hackers don't just attack your web server; they attack your employees' laptops and steal passwords from the dark web. Small startups can't afford expensive tools to monitor all these different areas."
    },
    {
        "title": "The Solution: Vuln-Shield",
        "bullets": [
            "A lightweight, centralized Cyber Defense Dashboard.",
            "Zero-Cost Setup: Built using Open Source tech (Node.js & Vanilla JS).",
            "360° Coverage: Scans Web Servers, Employee Devices, and Global Threat Intelligence databases simultaneously.",
            "Real-time Output: Automated PDF compliance report generation."
        ],
        "notes": "To solve this, I developed Vuln-Shield. It is a lightweight, centralized dashboard that provides enterprise-grade protection for zero cost. It monitors the web server, the local employee devices, and global threat databases all at the same time."
    },
    {
        "title": "High-Performance System Architecture",
        "bullets": [
            "Frontend: Pure Vanilla JavaScript Single Page Application (SPA) for ultra-fast, non-blocking DOM updates.",
            "Backend: Express.js API designed for asynchronous concurrent vulnerability scanning.",
            "Deployment: CI/CD integrated via GitHub and hosted live on Render."
        ],
        "notes": "Our architecture is built for speed. Instead of heavy frameworks, the frontend uses pure Vanilla JavaScript for lightning-fast manipulation. The backend is powered by Node.js, which uses an asynchronous, non-blocking model to run multiple heavy security scans concurrently."
    },
    {
        "title": "Methodology 1: Automated OWASP Auditing",
        "bullets": [
            "Automated parsing of HTTP Security Headers.",
            "Detects missing configurations critical to OWASP Top 10 vulnerabilities.",
            "Checks Include:",
            "  - Strict-Transport-Security (Prevents Downgrade attacks)",
            "  - X-Frame-Options (Prevents Clickjacking)",
            "  - X-Content-Type-Options (Prevents MIME-sniffing)"
        ],
        "notes": "The first module is the Web Scanner. It acts as an automated auditor that fetches and parses HTTP security headers from any target URL. It looks for missing headers that lead to OWASP Top 10 vulnerabilities, like Clickjacking, and flags them instantly."
    },
    {
        "title": "Methodology 2: Dark Web Threat Intelligence",
        "bullets": [
            "Live REST API integration with XposedOrNot.",
            "Scans target emails against global public data breach databases.",
            "Identifies exact breach sources (e.g., LinkedIn, Adobe) and compromised data types.",
            "Enables rapid password-rotation response."
        ],
        "notes": "The most powerful feature is our Threat Intelligence module. Vuln-Shield connects to a live, global Dark Web API. If an employee's email was leaked in a massive hack, our system alerts the admin immediately so they can force a password reset."
    },
    {
        "title": "Methodology 3: Zero-Trust Local OS Auditing",
        "bullets": [
            "Performs browser-fingerprinting and local OS evaluation.",
            "Verifies secure transport protocols.",
            "Gamified compliance scoring system (0-100%).",
            "Ensures endpoint security before granting network access."
        ],
        "notes": "The third module is the Device Audit. It evaluates the local machine running the dashboard, checking OS integrity and secure protocols. It outputs a compliance score, ensuring that an employee's laptop is safe before they access sensitive company data."
    },
    {
        "title": "Methodology 4: Laptop & Mobile Spyware Scanner",
        "bullets": [
            "Universal browser-based forensics engine detecting active spyware.",
            "Analyzes WebRTC, MediaDevices, and network data for rogue tracking.",
            "Identifies unencrypted HTTP traffic and missing Do-Not-Track headers.",
            "Instantly alerts users to device compromise or active hacking."
        ],
        "notes": "Our newest module is the Laptop and Mobile Spyware Scanner. Using advanced browser APIs, it detects if a device is being actively hacked or tracked. It flags unencrypted traffic and rogue hardware access, stopping spyware from exfiltrating sensitive data."
    },
    {
        "title": "Live AI Attack & Defense Simulator",
        "bullets": [
            "Interactive exploit lab demonstrating real-time attack vs AI defense.",
            "Showcases 4 scenarios: SQL Injection, AWS Secrets, Stored XSS, Android Backdoor.",
            "Executes simulated attacks and immediately deploys AI-generated code patches.",
            "Reduces time-to-fix (TTF) from hours to seconds."
        ],
        "notes": "Finally, to show this in action, we built a Live AI Attack and Defense Simulator. It simulates real-world hacks like SQL Injections. The moment an attack happens, our system generates and applies a secure code patch in seconds, turning Vuln-Shield from a monitoring tool into an active defense system."
    },
    {
        "title": "Automated PDF Executive Reporting",
        "bullets": [
            "Aggregates data from all three scan vectors.",
            "Utilizes jspdf and jspdf-autotable libraries.",
            "Generates a professional, exportable compliance document.",
            "Translates raw technical JSON data into readable formats for C-Level executives."
        ],
        "notes": "Finally, all of this data is useless if managers can't read it. So, I integrated an automated PDF generator that aggregates the Web Scan, Device Audit, and Threat Intel results into one professional executive report, ready to be handed to a CEO or compliance officer."
    },
    {
        "title": "Future Scope: The Road Ahead",
        "bullets": [
            "AI Auto-Fix: Integrating LLMs to automatically write the patch to fix vulnerable code.",
            "Automated Scheduling: Setting up Cron jobs to run Vuln-Shield audits every midnight automatically."
        ],
        "notes": "For the future scope, I plan to integrate Generative AI. Currently, Vuln-Shield finds the bugs. With an AI integration, Vuln-Shield will actually write the secure code needed to patch the server automatically."
    },
    {
        "title": "Conclusion",
        "bullets": [
            '"Security is not a product, but a process."',
            "Vuln-Shield proves that enterprise-grade security can be lightweight, fast, and accessible to startups.",
            "Thank You! Open for Questions."
        ],
        "notes": "In conclusion, Vuln-Shield proves that comprehensive cybersecurity doesn't have to be expensive or overly complicated. By unifying Web, Device, and Dark Web auditing, we create a stronger, faster defense. Thank you for your time, I am now open to any questions."
    }
]

# Generate the slides
for slide_data in slides_data:
    slide_layout = prs.slide_layouts[1] # Title and Content layout
    slide = prs.slides.add_slide(slide_layout)
    apply_dark_theme(slide)
    
    title = slide.shapes.title
    title.text = slide_data["title"]
    format_title(title)
    
    body = slide.placeholders[1]
    body.text = ""
    for bullet in slide_data["bullets"]:
        p = body.text_frame.add_paragraph()
        p.text = bullet
        p.level = 0 if not bullet.startswith("  -") else 1
    
    format_text(body, 28)
    slide.notes_slide.notes_text_frame.text = slide_data["notes"]

# Save presentation
ppt_path = "C:/Users/P52/.gemini/antigravity-ide/scratch/vuln-shield/VulnShield_Spectra26.pptx"
prs.save(ppt_path)
print(f"Presentation saved successfully at {ppt_path}")
