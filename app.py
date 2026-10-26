import os
import re
from datetime import datetime
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from flask import Flask, render_template, request, send_from_directory, url_for, abort


# Guard server-side fetching: prevent SSRF, DNS rebinding and unbounded responses.
import ipaddress
import socket
import uuid
from types import SimpleNamespace
from urllib.parse import urljoin, urlsplit, urlunsplit
import urllib3
from urllib3.util import Timeout

MAX_HTML_BYTES = 2 * 1024 * 1024
OUTPUT_TTL_SECONDS = 3600

def safe_get_html(raw_url):
    url = raw_url.strip()
    for hop in range(4):
        if len(url) > 2048 or any(ord(ch) < 32 for ch in url):
            raise ValueError("Invalid URL")
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Only public HTTP(S) URLs are supported")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if port not in (80, 443):
            raise ValueError("Only ports 80 and 443 are allowed")
        hostname = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        if not hostname or hostname == "localhost" or hostname.endswith((".localhost", ".local", ".internal", ".test")):
            raise ValueError("Local targets are forbidden")
        addresses = set(row[4][0] for row in socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM))
        if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
            raise ValueError("Private or reserved targets are forbidden")
        ip = sorted(addresses)[0]
        options = dict(host=ip, port=port, timeout=Timeout(connect=4, read=9), retries=False)
        if parsed.scheme == "https":
            options.update(cert_reqs="CERT_REQUIRED", assert_hostname=hostname, server_hostname=hostname)
        pool = (urllib3.HTTPSConnectionPool if parsed.scheme == "https" else urllib3.HTTPConnectionPool)(**options)
        response = None
        try:
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            response = pool.urlopen("GET", path, headers={
                "Host": hostname if port in (80, 443) else f"{hostname}:{port}",
                "User-Agent": "FindXAnalyzer/1.0",
                "Accept": "text/html,application/xhtml+xml",
                "Accept-Encoding": "identity",
            }, preload_content=False, redirect=False)
            if response.status in (301, 302, 303, 307, 308):
                if hop >= 3 or not response.headers.get("Location"):
                    raise ValueError("Too many redirects")
                url = urljoin(url, response.headers["Location"])
                continue
            if response.status >= 400:
                raise ValueError(f"HTTP {response.status}")
            content_type = response.headers.get("Content-Type", "").lower()
            if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
                raise ValueError("Page is not HTML")
            data = response.read(MAX_HTML_BYTES + 1, decode_content=False)
            if len(data) > MAX_HTML_BYTES:
                raise ValueError("Page larger than 2MB")
            match = re.search(r"charset\s*=\s*['\"]?([a-zA-Z0-9._-]+)", content_type)
            charset = match.group(1) if match else "utf-8"
            try:
                content = data.decode(charset, errors="replace")
            except LookupError:
                content = data.decode("utf-8", errors="replace")
            return SimpleNamespace(text=content)
        finally:
            if response is not None:
                response.release_conn()
                response.close()
            pool.close()
    raise ValueError("Too many redirects")


app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 12 * 1024

# আউটপুট ফোল্ডার তৈরি
OUTPUT_DIR = "output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def analyze_website(url: str) -> str:
    """
    ওয়েবসাইটের গঠন ও এক্সিকিউশন সিস্টেম পয়েন্ট বাই পয়েন্ট বিশ্লেষণ করে
    একটি প্রম্পট-স্টাইল টেক্সট রিটার্ন করে।
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/120.0.0.0 Safari/537.36"
    }

    try:
        resp = safe_get_html(url)
        resp.raise_for_status()
    except Exception:
        return "❌ URL ফেচ করতে ব্যর্থ। Public HTTP(S) URL ও SSL চেক করুন।"

    soup = BeautifulSoup(resp.text, "html.parser")

    # ---------- প্রম্পট ফরম্যাটে আউটপুট তৈরি ----------
    lines = []
    lines.append("=" * 70)
    lines.append("  🌐 ওয়েবসাইট এক্সিকিউশন অ্যানালাইসিস (পয়েন্ট বাই পয়েন্ট)")
    lines.append("=" * 70)
    lines.append(f"🔗 URL: {url}")
    lines.append(f"🕒 সময়: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    # ১. বেসিক ইনফরমেশন
    lines.append("📌 ১. বেসিক ইনফরমেশন")
    title_tag = soup.find("title")
    lines.append(f"   • টাইটেল: {title_tag.string.strip() if title_tag and title_tag.string else 'N/A'}")

    meta_desc = soup.find("meta", attrs={"name": "description"})
    if meta_desc and meta_desc.get("content"):
        lines.append(f"   • মেটা ডেসক্রিপশন: {meta_desc['content'].strip()}")
    else:
        lines.append("   • মেটা ডেসক্রিপশন: নেই")

    meta_keywords = soup.find("meta", attrs={"name": "keywords"})
    if meta_keywords and meta_keywords.get("content"):
        lines.append(f"   • মেটা কিওয়ার্ড: {meta_keywords['content'].strip()}")
    lines.append("")

    # ২. হেডিং স্ট্রাকচার
    lines.append("📌 ২. হেডিং স্ট্রাকচার (H1–H6)")
    headings = soup.find_all(re.compile("^h[1-6]$"))
    if headings:
        for h in headings:
            text = h.get_text(strip=True)
            if text:
                lines.append(f"   • <{h.name}> {text[:120]}")
    else:
        lines.append("   • কোনো হেডিং পাওয়া যায়নি।")
    lines.append("")

    # ৩. মূল প্যারাগ্রাফ কন্টেন্ট
    lines.append("📌 ৩. মূল প্যারাগ্রাফ কন্টেন্ট")
    paragraphs = soup.find_all("p")
    meaningful_ps = [p.get_text(strip=True) for p in paragraphs if len(p.get_text(strip=True)) > 20]
    if meaningful_ps:
        for i, p_text in enumerate(meaningful_ps[:20], 1):  # প্রথম ২০টি
            lines.append(f"   • [{i}] {p_text[:200]}")
    else:
        lines.append("   • উল্লেখযোগ্য প্যারাগ্রাফ পাওয়া যায়নি।")
    lines.append("")

    # ৪. লিস্ট (UL/OL)
    lines.append("📌 ৪. লিস্ট আইটেম")
    lists = soup.find_all(["ul", "ol"])
    if lists:
        for lst in lists:
            items = lst.find_all("li", recursive=False)
            for li in items:
                txt = li.get_text(strip=True)
                if txt:
                    lines.append(f"   • {txt[:150]}")
    else:
        lines.append("   • কোনো লিস্ট পাওয়া যায়নি।")
    lines.append("")

    # ৫. ফর্ম ও ইনপুট ফিল্ড (ইন্টারেকশন পয়েন্ট)
    lines.append("📌 ৫. ফর্ম ও ইনপুট ফিল্ড (ইউজার ইন্টারেকশন)")
    forms = soup.find_all("form")
    if forms:
        for idx, form in enumerate(forms, 1):
            action = form.get("action", "N/A")
            method = form.get("method", "GET").upper()
            lines.append(f"   • ফর্ম #{idx}: action='{action}', method='{method}'")
            inputs = form.find_all(["input", "textarea", "select", "button"])
            for inp in inputs:
                inp_type = inp.get("type", inp.name)
                inp_name = inp.get("name", inp.get("id", "unnamed"))
                placeholder = inp.get("placeholder", "")
                lines.append(f"       - {inp_type}: name='{inp_name}' placeholder='{placeholder}'")
    else:
        lines.append("   • কোনো ফর্ম পাওয়া যায়নি।")
    lines.append("")

    # ৬. বাটন ও ক্লিকযোগ্য এলিমেন্ট
    lines.append("📌 ৬. বাটন ও ক্লিকযোগ্য এলিমেন্ট")
    buttons = soup.find_all(["button", "a"])
    clickable = []
    for btn in buttons:
        text = btn.get_text(strip=True)
        if text and len(text) < 50:
            clickable.append(f"{btn.name.upper()}: '{text}'")
    if clickable:
        for c in clickable[:30]:  # প্রথম ৩০টি
            lines.append(f"   • {c}")
    else:
        lines.append("   • কোনো দৃশ্যমান ক্লিকযোগ্য এলিমেন্ট পাওয়া যায়নি।")
    lines.append("")

    # ৭. স্ক্রিপ্ট ও এক্সটার্নাল রিসোর্স (এক্সিকিউশন সিস্টেম)
    lines.append("📌 ৭. স্ক্রিপ্ট ও এক্সটার্নাল রিসোর্স (এক্সিকিউশন সিস্টেম)")
    scripts = soup.find_all("script")
    inline_scripts = [s for s in scripts if not s.get("src") and s.string]
    external_scripts = [s["src"] for s in scripts if s.get("src")]
    if external_scripts:
        lines.append(f"   • এক্সটার্নাল স্ক্রিপ্ট: {len(external_scripts)} টি")
        for src in external_scripts[:10]:
            lines.append(f"       - {src}")
    if inline_scripts:
        lines.append(f"   • ইনলাইন স্ক্রিপ্ট: {len(inline_scripts)} টি")
        for i, s in enumerate(inline_scripts[:5], 1):
            snippet = s.string.strip()[:200].replace("\n", " ")
            lines.append(f"       - [{i}] {snippet}...")
    if not external_scripts and not inline_scripts:
        lines.append("   • কোনো স্ক্রিপ্ট পাওয়া যায়নি।")

    lines.append("")
    lines.append("=" * 70)
    lines.append("✅ বিশ্লেষণ সম্পন্ন।")
    lines.append("=" * 70)

    return "\n".join(lines)


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    url = request.form.get("url", "").strip()
    if not url:
        return render_template("index.html", error="অনুগ্রহ করে একটি URL দিন।")

    # স্কিম না থাকলে https:// যোগ করা
    if not urlparse(url).scheme:
        url = "https://" + url

    report = analyze_website(url)

    # টেক্সট ফাইল হিসেবে সেভ
    filename = f"findx_{uuid.uuid4().hex}.txt"
    filepath = os.path.join(OUTPUT_DIR, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(report)

    return render_template("result.html", report=report, filename=filename)


@app.route("/download/<filename>")
def download(filename):
    if not re.fullmatch(r'findx_[0-9a-f]{32}\\.txt', filename):
        abort(404)
    return send_from_directory(OUTPUT_DIR, filename, as_attachment=True, download_name='findx-analysis.txt')


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get('PORT', '10000')))
