
import re
import ipaddress
from urllib.parse import urlparse

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
import pickle


# 1. Demonstration dataset
# 0 = Legitimate, 1 = Phishing
data = [
    ("https://www.google.com", 0),
    ("https://www.wikipedia.org", 0),
    ("https://www.microsoft.com", 0),
    ("https://www.amazon.com", 0),
    ("https://www.github.com", 0),
    ("https://www.python.org", 0),
    ("https://www.apple.com", 0),
    ("https://www.bbc.com", 0),
    ("https://www.linkedin.com", 0),
    ("https://www.youtube.com", 0),

    ("http://paypal-login-verify.xyz", 1),
    ("http://secure-account-update.top", 1),
    ("http://free-prize-claim.click", 1),
    ("http://bank-password-verify.tk", 1),
    ("http://login-account-security.ml", 1),
    ("http://gift-card-claim.ga", 1),
    ("http://verify-user-password.cf", 1),
    ("http://account-update-login.xyz", 1),
    ("http://secure-bank-login.top", 1),
    ("http://prize-winner-claim.click", 1),
]


# 2. Extract numerical features from a URL
def extract_features(url):
    url = url.strip()
    parsed = urlparse(url if "://" in url else "http://" + url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""

    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 0

    suspicious_words = [
        "login", "verify", "secure", "update",
        "account", "bank", "password", "free",
        "prize", "gift", "claim"
    ]

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
        sum(word in url.lower() for word in suspicious_words),
        int(hostname.lower().endswith(
            (".xyz", ".top", ".tk", ".click", ".ml", ".ga", ".cf")
        )),
    ]


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


# 3. Prepare the training data
df = pd.DataFrame(data, columns=["url", "label"])

X = pd.DataFrame(
    [extract_features(url) for url in df["url"]],
    columns=FEATURE_NAMES
)
y = df["label"]


# 4. Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.30,
    random_state=42,
    stratify=y
)


# 5. Train the Random Forest model
model = Pipeline([
    ("scaler", StandardScaler()),
    ("classifier", RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced"
    ))
])

model.fit(X_train, y_train)


# 6. Evaluate the model
predictions = model.predict(X_test)

print("\n===== LinkShield AI: Model Evaluation =====")
print("Test accuracy:", round(accuracy_score(y_test, predictions) * 100, 2), "%")
print("\nClassification report:")
print(classification_report(
    y_test,
    predictions,
    labels=[0, 1],
    target_names=["Legitimate", "Phishing"],
    zero_division=0
))


# 7. Save the trained model
with open("linkshield_model.pkl", "wb") as file:
    pickle.dump(model, file)

print("Model saved as linkshield_model.pkl")
print("Training completed successfully!")