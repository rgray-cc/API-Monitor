#!/usr/bin/env python3
import os, re, hashlib, time, difflib, json, smtplib, socket
from email.mime.text import MIMEText
from pathlib import Path
from typing import Tuple, Optional
import requests
from bs4 import BeautifulSoup

STATE_DIR = Path(os.getenv("STATE_DIR", "./state"))
URLS_FILE = Path(os.getenv("URLS_FILE", "./urls.txt"))

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")  # set in GitHub Secrets
REQ_TIMEOUT = int(os.getenv("REQ_TIMEOUT", "30"))
USER_AGENT = os.getenv("USER_AGENT", f"DocMonitor/1.0 (+{socket.gethostname()})")
MAX_DIFF_LINES = int(os.getenv("MAX_DIFF_LINES", "120"))

STATE_DIR.mkdir(parents=True, exist_ok=True)

def load_urls(file: Path) -> list[str]:
    if not file.exists(): return []
    urls = []
    for line in file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        urls.append(line)
    return urls

def url_key(url: str) -> str:
    return hashlib.md5(url.encode("utf-8")).hexdigest()

def fetch_clean_text(url: str) -> Tuple[str, str]:
    headers = {"User-Agent": USER_AGENT}
    r = requests.get(url, headers=headers, timeout=REQ_TIMEOUT)
    r.raise_for_status()
    html = r.text
    soup = BeautifulSoup(html, "lxml")
    for tag in soup(["script", "style", "noscript"]): tag.extract()
    text = soup.get_text(separator="\n")
    text = re.sub(r"\s+\n", "\n", text)
    text = re.sub(r"\n{2,}", "\n\n", text).strip()
    text = re.sub(r"Updated:?\s+\d{4}-\d{2}-\d{2}.*", "", text, flags=re.IGNORECASE)
    return text, html

def load_previous(key: str) -> Tuple[Optional[str], Optional[str]]:
    txt_path = STATE_DIR / f"{key}.txt"
    raw_path = STATE_DIR / f"{key}.raw.html"
    old_txt = txt_path.read_text() if txt_path.exists() else None
    old_raw = raw_path.read_text() if raw_path.exists() else None
    return old_txt, old_raw

def save_current(key: str, clean_text: str, raw_html: str) -> None:
    (STATE_DIR / f"{key}.txt").write_text(clean_text)
    (STATE_DIR / f"{key}.raw.html").write_text(raw_html)

def unified_diff(old: str, new: str, url: str) -> str:
    diff = difflib.unified_diff(
        old.splitlines(), new.splitlines(),
        fromfile=f"{url} (old)", tofile=f"{url} (new)", lineterm=""
    )
    lines = list(diff)
    if len(lines) > MAX_DIFF_LINES:
        lines = lines[:MAX_DIFF_LINES] + ["", f"...(trimmed to {MAX_DIFF_LINES} lines)"]
    return "\n".join(lines)

def post_slack(msg: str):
    if not SLACK_WEBHOOK_URL: return
    try:
        requests.post(SLACK_WEBHOOK_URL, data=json.dumps({"text": msg}), timeout=15)
    except Exception as e:
        print(f"[warn] Slack post failed: {e}")

def alert_changed(url: str, diff_text: str):
    title = f"[DocMonitor] Change detected: {url}"
    post_slack(f"{title}\n\n```{diff_text[:3600]}```")

def main():
    urls = load_urls(URLS_FILE)
    if not urls:
        print(f"No URLs found in {URLS_FILE}.")
        return
    for url in urls:
        key = url_key(url)
        try:
            new_txt, new_raw = fetch_clean_text(url)
            old_txt, _ = load_previous(key)
            new_hash = hashlib.sha256(new_txt.encode("utf-8")).hexdigest()
            old_hash = hashlib.sha256(old_txt.encode("utf-8")).hexdigest() if old_txt else None

            if old_hash and old_hash != new_hash:
                diff_text = unified_diff(old_txt, new_txt, url)
                print(f"[{time.strftime('%F %T')}] CHANGE: {url}")
                alert_changed(url, diff_text)
            else:
                print(f"[{time.strftime('%F %T')}] no change: {url}")

            save_current(key, new_txt, new_raw)
        except Exception as e:
            print(f"[error] {url}: {e}")

if __name__ == "__main__":
    main()
