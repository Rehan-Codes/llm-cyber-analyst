import os, shutil, glob, datetime, subprocess

# Source project artifacts
SRC = r"C:\Users\rabbasi\llm-cyber-analyst\run_artifacts"
# Destination root in OneDrive
DESTROOT = r"C:\Users\rabbasi\OneDrive - Septodont\Documents\Cybersecurity\llm-cyber-analyst"

os.makedirs(DESTROOT, exist_ok=True)
stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
dest = os.path.join(DESTROOT, stamp)
os.makedirs(dest, exist_ok=True)

# If we have HTML but not PDF, try Edge headless to print PDF
html = os.path.join(SRC, "report.html")
pdf  = os.path.join(SRC, "report.pdf")
if os.path.exists(html) and not os.path.exists(pdf):
    for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")):
        if not base: continue
        edge = os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe")
        if os.path.exists(edge):
            subprocess.run([edge, "--headless", "--disable-gpu", f"--print-to-pdf={pdf}", html])

# Copy artifacts
patterns = ["*.json", "*.syft", "*.syft.json", "report.pdf", "report.html"]
copied = 0
for pat in patterns:
    for f in glob.glob(os.path.join(SRC, pat)):
        shutil.copy2(f, dest)
        copied += 1

print(f"Exported {copied} files to {dest}")
