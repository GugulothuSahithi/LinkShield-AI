
import http.server
import socketserver
import threading
import webbrowser
import json
import pickle
import re
import ipaddress
from urllib.parse import urlparse

import pandas as pd

PORT = 8000

# Load the already-trained Random Forest model
try:
    with open("linkshield_model.pkl", "rb") as file:
        model = pickle.load(file)
    MODEL_ERROR = None
    print("Random Forest model loaded successfully!")
except Exception as error:
    model = None
    MODEL_ERROR = str(error)
    print("ML model could not be loaded:", error)


FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "dot_count",
    "hyphen_count",
    "at_count",
    "slash_count",
    "path_length",
    "uses_https",
    "has_ip_address",
    "suspicious_word_count",
    "risky_tld",
]


def extract_features(url):
    parsed = urlparse(url if "://" in url else "http://" + url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""

    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 0

    words = [
        "login", "verify", "secure", "update", "account",
        "bank", "password", "free", "prize", "gift", "claim"
    ]

    risky_tlds = (
        ".xyz", ".top", ".tk", ".click", ".ml", ".ga", ".cf"
    )

    return [
        len(url),
        len(hostname),
        url.count("."),
        url.count("-"),
        url.count("@"),
        url.count("//"),
        len(path),
        int(parsed.scheme.lower() == "https"),
        has_ip,
        sum(word in url.lower() for word in words),
        int(hostname.lower().endswith(risky_tlds)),
    ]


def analyze_url(url):
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    reasons = []

    if parsed.scheme != "https":
        reasons.append("Does not use HTTPS")

    try:
        ipaddress.ip_address(host)
        reasons.append("Uses an IP address instead of a domain name")
    except ValueError:
        pass

    if "@" in url:
        reasons.append("Contains an @ symbol")

    if len(url) > 75:
        reasons.append("The URL is unusually long")

    if len(host.split(".")) > 4:
        reasons.append("Contains many subdomains")

    if host.count("-") > 2:
        reasons.append("Contains several hyphens in the domain")

    words = [
        "login", "verify", "secure", "update", "account",
        "bank", "password", "free", "prize", "gift", "claim"
    ]
    found = [word for word in words if word in url.lower()]

    if found:
        reasons.append(
            "Contains potentially suspicious words: " + ", ".join(found)
        )

    endings = (".xyz", ".top", ".tk", ".click", ".zip", ".ml", ".ga", ".cf")

    for ending in endings:
        if host.endswith(ending):
            reasons.append("Uses a domain ending that warrants caution: " + ending)
            break

    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly"]

    if host in shorteners:
        reasons.append("Uses a shortened URL")

    ml_result = "Unavailable"
    confidence = None

    if model is not None:
        features = pd.DataFrame(
            [extract_features(url)],
            columns=FEATURE_NAMES
        )

        prediction = int(model.predict(features)[0])
        probabilities = model.predict_proba(features)[0]
        confidence = round(float(max(probabilities)) * 100, 2)

        ml_result = (
            "Potentially Phishing"
            if prediction == 1
            else "Likely Legitimate"
        )

    return {
        "reasons": reasons,
        "ml_result": ml_result,
        "confidence": confidence,
    }


PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LinkShield AI | Safer Links</title>
<style>
* { box-sizing: border-box; }
body {
    margin: 0; font-family: Arial, sans-serif; color: #172b4d;
    background: #f4f8ff;
}
header {
    background: white; border-bottom: 1px solid #e2eaf7;
    padding: 18px 7%; display: flex; justify-content: space-between;
    align-items: center; gap: 15px;
}
.brand { display: flex; align-items: center; gap: 12px; }
.logo {
    background: #1769ff; color: white; border-radius: 14px;
    width: 48px; height: 48px; display: grid;
    place-items: center; font-size: 25px;
}
.brand h2 { margin: 0; font-size: 23px; }
.brand h2 span { color: #1769ff; }
.brand p { margin: 5px 0 0; color: #64748b; font-size: 13px; }
nav { color: #526784; font-size: 14px; }
main { max-width: 1150px; margin: auto; padding: 55px 24px 30px; }
.hero { text-align: center; margin-bottom: 30px; }
.shield { font-size: 48px; margin-bottom: 12px; }
.hero h1 { font-size: clamp(32px, 5vw, 48px); margin: 0 0 12px; }
.hero h1 span { color: #1769ff; }
.subtitle {
    color: #536783; font-size: 17px; line-height: 1.6;
    margin: 0 auto 28px;
}
.check-form {
    display: flex; max-width: 790px; margin: auto; gap: 12px;
}
.input-wrap {
    flex: 1; min-width: 0; display: flex; align-items: center;
    gap: 10px; background: white; border: 1px solid #cbdaf0;
    border-radius: 12px; padding: 0 16px;
}
.input-wrap span { font-size: 21px; color: #7185a3; }
input {
    width: 100%; min-width: 0; padding: 17px 0; font-size: 15px;
    border: none; outline: none; background: transparent; color: #172b4d;
}
button {
    border: none; border-radius: 12px; padding: 0 28px;
    background: #1769ff; color: white; font-size: 16px;
    font-weight: bold; cursor: pointer;
}
button:hover { background: #0754dc; }
button:disabled { opacity: .7; cursor: wait; }
#result {
    display: none; margin: 28px auto 0; max-width: 790px;
    padding: 22px; border-radius: 14px; text-align: left;
    border: 1px solid #dbe5f3; background: white; overflow-wrap: anywhere;
}
#result h2 { margin: 0 0 10px; font-size: 22px; }
#result p { line-height: 1.6; }
#result ul { padding-left: 22px; line-height: 1.9; }
.safe { border-color: #9bdfbd !important; background: #f0fbf5 !important; }
.safe h2 { color: #147744; }
.warn { border-color: #f0d08b !important; background: #fff9ec !important; }
.warn h2 { color: #9a6500; }
.bad { border-color: #f2b5b5 !important; background: #fff1f1 !important; }
.bad h2 { color: #c1272d; }
.features {
    display: grid; grid-template-columns: repeat(3, 1fr);
    gap: 18px; margin-top: 48px;
}
.feature {
    background: white; padding: 22px 18px;
    border: 1px solid #e2eaf7; border-radius: 14px;
}
.feature-icon { font-size: 25px; margin-bottom: 12px; }
.feature h3 { font-size: 16px; margin: 0 0 9px; }
.feature p { color: #64748b; font-size: 14px; line-height: 1.6; margin: 0; }
.notice {
    max-width: 790px; margin: 35px auto 0; text-align: center;
    font-size: 13px; line-height: 1.7; color: #718096;
}
footer {
    text-align: center; padding: 24px; border-top: 1px solid #e2eaf7;
    color: #718096; background: white; font-size: 13px; margin-top: 35px;
}
@media (max-width: 650px) {
    header { padding: 15px 5%; }
    nav { display: none; }
    main { padding: 38px 16px 20px; }
    .check-form { flex-direction: column; }
    .input-wrap { width: 100%; }
    button { min-height: 52px; }
    .features { grid-template-columns: 1fr; margin-top: 30px; }
    #result { padding: 18px; }
}
</style>
</head>
<body>
<header>
    <div class="brand">
        <div class="logo">🔗</div>
        <div>
            <h2>LinkShield <span>AI</span></h2>
            <p>Safer Links. Safer You.</p>
        </div>
    </div>
    <nav>URL SECURITY &nbsp; | &nbsp; PHISHING AWARENESS</nav>
</header>

<main>
<section class="hero">
    <div class="shield">🛡️</div>
    <h1>Check Before <span>You Click.</span></h1>
    <p class="subtitle">
        Check a website link for common phishing warning signs.<br>
        Paste a URL below to get started.
    </p>
    <form class="check-form" id="checkForm">
        <div class="input-wrap">
            <span>🔗</span>
            <input id="url" type="text" placeholder="https://example.com"
                   autocomplete="url" aria-label="Website URL" required>
        </div>
        <button id="checkButton" type="submit">🔍 Check Link</button>
    </form>
    <div id="result" role="status" aria-live="polite"></div>
</section>

<section class="features">
    <article class="feature">
        <div class="feature-icon">🔎</div>
        <h3>Suspicious Patterns</h3>
        <p>Checks URLs for common phishing indicators and unusual domains.</p>
    </article>
    <article class="feature">
        <div class="feature-icon">⚡</div>
        <h3>Machine Learning Analysis</h3>
        <p>A Random Forest model analyses URL features and provides a prediction.</p>
    </article>
    <article class="feature">
        <div class="feature-icon">🔐</div>
        <h3>Browse Carefully</h3>
        <p>Learn to recognize warning signs before opening unfamiliar links.</p>
    </article>
</section>

<p class="notice">
    Important: This is a student prototype using URL patterns and a
    demonstration ML model. Predictions are not guarantees of website safety.
    Avoid entering passwords or personal information on unfamiliar websites.
</p>
</main>

<footer>
    LinkShield AI &copy; 2026 &nbsp; | &nbsp; Think before you click.
</footer>

<script>
const form = document.getElementById("checkForm");
const input = document.getElementById("url");
const result = document.getElementById("result");
const button = document.getElementById("checkButton");

form.addEventListener("submit", async function(event) {
    event.preventDefault();

    const value = input.value.trim();
    if (!value) return;

    let parsed;
    try {
        parsed = new URL(value);
    } catch {
        showError("Invalid URL", "Enter a complete URL, such as https://example.com");
        return;
    }

    if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname) {
        showError("Unsupported URL", "Enter a website address starting with http:// or https://.");
        return;
    }

    button.disabled = true;
    button.textContent = "Analysing...";
    result.className = "";
    result.style.display = "block";
    result.textContent = "Checking URL patterns and running the ML model...";

    try {
        const response = await fetch("/analyze", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({url: value})
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Analysis failed");

        displayResult(data);
    } catch (error) {
        showError("Analysis Error", error.message || "Could not analyse this URL.");
    } finally {
        button.disabled = false;
        button.textContent = "🔍 Check Link";
    }
});

function showError(title, message) {
    result.className = "bad";
    result.replaceChildren();

    const heading = document.createElement("h2");
    heading.textContent = "⚠️ " + title;

    const paragraph = document.createElement("p");
    paragraph.textContent = message;

    result.append(heading, paragraph);
    result.style.display = "block";
}

function displayResult(data) {
    result.replaceChildren();

    const reasons = data.reasons || [];
    const isPhishing = data.ml_result === "Potentially Phishing";
    const hasWarnings = reasons.length > 0;

    result.className = isPhishing || reasons.length >= 3
        ? "bad"
        : hasWarnings ? "warn" : "safe";

    const heading = document.createElement("h2");
    heading.textContent = isPhishing
        ? "⚠️ ML Model: Potentially Phishing"
        : data.ml_result === "Likely Legitimate"
            ? "✓ ML Model: Likely Legitimate"
            : "⚠️ ML Model Unavailable";
    result.appendChild(heading);

    const prediction = document.createElement("p");
    prediction.textContent = data.confidence === null
        ? "The model prediction is unavailable."
        : "Model confidence: " + data.confidence +
          "%. This is the model's confidence, not a guarantee of accuracy.";
    result.appendChild(prediction);

    const subheading = document.createElement("h3");
    subheading.textContent = "Rule-Based URL Check";
    result.appendChild(subheading);

    const summary = document.createElement("p");
    summary.textContent = hasWarnings
        ? "The following warning signs were detected:"
        : "No warning signs were detected by the basic rules.";
    result.appendChild(summary);

    if (hasWarnings) {
        const list = document.createElement("ul");
        reasons.forEach(function(reason) {
            const item = document.createElement("li");
            item.textContent = reason;
            list.appendChild(item);
        });
        result.appendChild(list);
    }

    const note = document.createElement("p");
    note.textContent =
        "This prototype uses a very small demonstration dataset. " +
        "Its predictions may be wrong; do not rely on them to establish website safety.";
    result.appendChild(note);

    result.style.display = "block";
}
</script>
</body>
</html>
"""


class Handler(http.server.BaseHTTPRequestHandler):
    def send_json(self, status, payload):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return

        data = PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path != "/analyze":
            self.send_json(404, {"error": "Endpoint not found"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))

            if length <= 0 or length > 10000:
                self.send_json(400, {"error": "Invalid request size"})
                return

            body = json.loads(self.rfile.read(length).decode("utf-8"))
            url = body.get("url", "")

            if not isinstance(url, str) or not url.strip():
                self.send_json(400, {"error": "Please enter a URL"})
                return

            url = url.strip()
            parsed = urlparse(url)

            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                self.send_json(400, {"error": "Enter a valid HTTP or HTTPS URL"})
                return

            if model is None:
                self.send_json(503, {
                    "error": "ML model could not be loaded. Check linkshield_model.pkl."
                })
                return

            result = analyze_url(url)
            self.send_json(200, result)

        except Exception:
            self.send_json(400, {"error": "Could not analyse this URL"})

    def log_message(self, *args):
        pass


class Server(socketserver.TCPServer):
    allow_reuse_address = True


url = "http://localhost:%d" % PORT

with Server(("", PORT), Handler) as server:
    print("LinkShield AI is running at " + url)
    print("Press Ctrl+C to stop.")
    threading.Timer(1, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")