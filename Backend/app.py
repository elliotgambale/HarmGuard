import asyncio
import io
import logging
import os
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import httpx
import requests
from bs4 import BeautifulSoup
from detoxify import Detoxify
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from PIL import Image
from pydantic import BaseModel
from transformers import pipeline

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

MAX_TEXT_CHARS = 10000
MAX_IMAGES = 8
TEXT_THRESHOLD = 0.5
HARMFUL_THRESHOLD = 0.4
VT_FLAG_THRESHOLD = 3
IMAGE_TIMEOUT = 10
YOUNG_CERT_DAYS = 7

SCRIPT_PATTERNS = {
    "base64_eval": re.compile(r"eval\s*\(\s*atob\s*\(", re.IGNORECASE),
    "crypto_miner": re.compile(r"(?:coinhive|cryptominer)", re.IGNORECASE),
    "char_code_obfuscation": re.compile(
        r"fromCharCode\s*\(\s*(?:\d+\s*,\s*){7,}\d+\s*\)",
        re.IGNORECASE,
    ),
    "keylogging_fetch": re.compile(r"onkeypress[\s\S]{0,200}?fetch", re.IGNORECASE),
    "dynamic_function": re.compile(r"new\s+Function\s*\(", re.IGNORECASE),
}

SCRIPT_PATTERN_WEIGHTS = {
    "base64_eval": 0.6,
    "crypto_miner": 1.0,
    "char_code_obfuscation": 0.2,
    "keylogging_fetch": 0.8,
    "dynamic_function": 0.35,
}

WEIGHTS = {
    "text_toxicity": 0.30,
    "image_analysis": 0.25,
    "script_scanning": 0.20,
    "domain_reputation": 0.15,
    "metadata_checks": 0.10,
}

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

detox = Detoxify("unbiased")
image_classifier = pipeline(
    "image-classification",
    model="Falconsai/nsfw_image_detection",
)
virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()


class URLRequest(BaseModel):
    url: str


def normalize_url(raw_url: str) -> str:
    if re.match(r"^https?://", raw_url, re.IGNORECASE):
        return raw_url
    return f"https://{raw_url}"


def label_is_unsafe(label: str) -> bool:
    normalized = label.lower()
    return "nsfw" in normalized or "unsafe" in normalized


def score_text_toxicity(text: str) -> dict[str, object]:
    raw_results = detox.predict(text)
    results: dict[str, float] = {}
    for key, value in raw_results.items():
        try:
            results[key] = float(value.item())
        except AttributeError:
            results[key] = float(value)

    score = results.get("toxicity", results.get("toxic", 0.0))
    return {
        "score": score,
        "flagged": score >= TEXT_THRESHOLD,
        "details": {
            "threshold": TEXT_THRESHOLD,
            "all_scores": results,
        },
    }


def score_images(soup: BeautifulSoup, page_url: str) -> dict[str, object]:
    image_urls: list[str] = []
    seen_urls: set[str] = set()

    for img in soup.find_all("img"):
        src = (img.get("src") or "").strip()
        if not src:
            continue
        full_url = urljoin(page_url, src)
        if full_url in seen_urls:
            continue
        seen_urls.add(full_url)
        image_urls.append(full_url)
        if len(image_urls) >= MAX_IMAGES:
            break

    unsafe_count = 0
    processed = 0
    flagged_urls: list[str] = []

    for image_url in image_urls:
        try:
            response = requests.get(image_url, timeout=IMAGE_TIMEOUT)
            response.raise_for_status()
            image = Image.open(io.BytesIO(response.content)).convert("RGB").resize((224, 224))
            predictions = image_classifier(image)
            top_prediction = predictions[0] if predictions else {}
            label = str(top_prediction.get("label", ""))
            if label_is_unsafe(label):
                unsafe_count += 1
                flagged_urls.append(image_url)
            processed += 1
        except Exception as exc:
            logger.info("Image analysis skipped for %s: %s", image_url, exc)

    score = unsafe_count / processed if processed else 0.0
    return {
        "score": score,
        "flagged": score > 0.0,
        "details": {
            "images_found": len(image_urls),
            "images_processed": processed,
            "unsafe_images": unsafe_count,
            "flagged_image_urls": flagged_urls,
        },
    }


def score_scripts(soup: BeautifulSoup) -> dict[str, object]:
    weighted_hits = 0.0
    pattern_hits: dict[str, int] = {name: 0 for name in SCRIPT_PATTERNS}
    scripts_scanned = 0
    suspicious_scripts = 0

    for script in soup.find_all("script"):
        script_text = script.get_text(" ", strip=True)
        if not script_text:
            continue
        scripts_scanned += 1
        script_weight = 0.0
        for name, pattern in SCRIPT_PATTERNS.items():
            match_count = len(pattern.findall(script_text))
            if match_count:
                pattern_hits[name] += match_count
                script_weight += match_count * SCRIPT_PATTERN_WEIGHTS[name]
        if script_weight > 0:
            suspicious_scripts += 1
            weighted_hits += min(script_weight, 1.0)

    score = min(weighted_hits / 2.5, 1.0)
    strong_script_signal = (
        pattern_hits["base64_eval"] > 0
        or pattern_hits["crypto_miner"] > 0
        or pattern_hits["keylogging_fetch"] > 0
        or (pattern_hits["dynamic_function"] > 0 and pattern_hits["char_code_obfuscation"] > 0)
    )
    return {
        "score": score,
        "flagged": strong_script_signal or score >= 0.55,
        "details": {
            "scripts_scanned": scripts_scanned,
            "suspicious_scripts": suspicious_scripts,
            "weighted_hits": round(weighted_hits, 3),
            "total_pattern_hits": sum(pattern_hits.values()),
            "pattern_hits": pattern_hits,
        },
    }


def score_domain_reputation(page_url: str) -> dict[str, object]:
    domain = urlparse(page_url).hostname or ""
    if not domain:
        return {
            "score": 0.0,
            "flagged": False,
            "details": {
                "domain": domain,
                "malicious_count": 0,
                "vt_lookup": "missing-domain",
            },
        }

    if not virustotal_api_key:
        return {
            "score": 0.0,
            "flagged": False,
            "details": {
                "domain": domain,
                "malicious_count": 0,
                "vt_lookup": "missing-api-key",
            },
        }

    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": virustotal_api_key},
            timeout=10,
        )
        response.raise_for_status()
        payload = response.json()
        stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious_count = int(stats.get("malicious", 0))
    except Exception as exc:
        logger.warning("VirusTotal lookup failed for %s: %s", domain, exc)
        return {
            "score": 0.0,
            "flagged": False,
            "details": {
                "domain": domain,
                "malicious_count": 0,
                "vt_lookup": f"lookup-failed: {exc}",
            },
        }

    score = min(malicious_count / 10, 1.0)
    return {
        "score": score,
        "flagged": malicious_count >= VT_FLAG_THRESHOLD,
        "details": {
            "domain": domain,
            "malicious_count": malicious_count,
            "threshold": VT_FLAG_THRESHOLD,
            "vt_lookup": "ok",
        },
    }


def get_certificate_age_days(hostname: str) -> int | None:
    context = ssl.create_default_context()
    with socket.create_connection((hostname, 443), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as wrapped_socket:
            certificate = wrapped_socket.getpeercert()

    not_before = certificate.get("notBefore")
    if not not_before:
        return None

    issued_at = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    return max((datetime.now(timezone.utc) - issued_at).days, 0)


def is_suspicious_hidden_iframe(iframe, page_url: str) -> bool:
    src = (iframe.get("src") or "").strip()
    if not src:
        return False

    full_src = urljoin(page_url, src)
    iframe_host = urlparse(full_src).hostname
    page_host = urlparse(page_url).hostname
    is_cross_origin = bool(iframe_host and page_host and iframe_host != page_host)

    width = (iframe.get("width") or "").strip()
    height = (iframe.get("height") or "").strip()
    tiny_dimensions = width in {"0", "1"} or height in {"0", "1"}

    return is_cross_origin or tiny_dimensions


def score_metadata(page_url: str, soup: BeautifulSoup) -> dict[str, object]:
    parsed = urlparse(page_url)
    flags = {
        "non_https_url": parsed.scheme.lower() != "https",
        "hidden_iframe": False,
        "young_ssl_certificate": False,
    }
    metadata_signals = {
        "hidden_iframe": False,
    }

    for iframe in soup.find_all("iframe"):
        style = (iframe.get("style") or "").replace(" ", "").lower()
        is_hidden = (
            "display:none" in style
            or "visibility:hidden" in style
            or "opacity:0" in style
            or iframe.has_attr("hidden")
        )
        if not is_hidden:
            continue
        flags["hidden_iframe"] = True
        if is_suspicious_hidden_iframe(iframe, page_url):
            metadata_signals["hidden_iframe"] = True
            break

    cert_age_days = None
    if parsed.scheme.lower() == "https" and parsed.hostname:
        try:
            cert_age_days = get_certificate_age_days(parsed.hostname)
            flags["young_ssl_certificate"] = cert_age_days is not None and cert_age_days < YOUNG_CERT_DAYS
        except Exception as exc:
            logger.info("SSL metadata unavailable for %s: %s", parsed.hostname, exc)

    score = 0.0
    if flags["non_https_url"]:
        score += 0.55
    if metadata_signals["hidden_iframe"]:
        score += 0.25
    if flags["young_ssl_certificate"]:
        score += 0.10

    metadata_only_flag = flags["non_https_url"] and metadata_signals["hidden_iframe"]
    return {
        "score": min(score, 1.0),
        "flagged": metadata_only_flag,
        "details": {
            "flags": flags,
            "signals": metadata_signals,
            "certificate_age_days": cert_age_days,
        },
    }


def build_reasons(breakdown: dict[str, dict[str, object]]) -> list[str]:
    reason_map = {
        "text_toxicity": "high text toxicity",
        "image_analysis": "unsafe images",
        "script_scanning": "suspicious scripts",
        "domain_reputation": "poor domain reputation",
        "metadata_checks": "suspicious page metadata",
    }
    return [reason_map[name] for name, result in breakdown.items() if result["flagged"]]


@app.post("/analyze")
async def analyze(request: URLRequest):
    page_url = normalize_url(request.url.strip())
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/112.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            response = await client.get(page_url, timeout=10.0, headers=headers)
            response.raise_for_status()
    except Exception as exc:
        logger.error("Fetch error (%s): %s", type(exc).__name__, exc)
        raise HTTPException(status_code=400, detail=f"Failed to fetch URL: {exc}") from exc

    soup = BeautifulSoup(response.text, "html.parser")
    text = " ".join(soup.stripped_strings)[:MAX_TEXT_CHARS]

    text_result, image_result, domain_result, metadata_result = await asyncio.gather(
        asyncio.to_thread(score_text_toxicity, text),
        asyncio.to_thread(score_images, soup, page_url),
        asyncio.to_thread(score_domain_reputation, page_url),
        asyncio.to_thread(score_metadata, page_url, soup),
    )
    script_result = score_scripts(soup)

    breakdown = {
        "text_toxicity": text_result,
        "image_analysis": image_result,
        "script_scanning": script_result,
        "domain_reputation": domain_result,
        "metadata_checks": metadata_result,
    }

    risk_score = sum(breakdown[name]["score"] * WEIGHTS[name] for name in WEIGHTS)
    strong_signal_names = {
        "text_toxicity",
        "image_analysis",
        "script_scanning",
        "domain_reputation",
    }
    strong_signal_flagged = any(breakdown[name]["flagged"] for name in strong_signal_names)
    metadata_supported = metadata_result["score"] >= 0.6 and (
        script_result["flagged"] or domain_result["flagged"]
    )
    is_harmful = strong_signal_flagged or metadata_supported or risk_score >= HARMFUL_THRESHOLD
    reasons = build_reasons(breakdown)

    return {
        "risk_score": risk_score,
        "is_harmful": is_harmful,
        "threshold": HARMFUL_THRESHOLD,
        "decision_rule": "strong-signal-or-supported-metadata-or-threshold",
        "weights": WEIGHTS,
        "reasons": reasons,
        "breakdown": breakdown,
    }
