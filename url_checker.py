import pandas as pd
import joblib
import requests
from urllib.parse import urlparse
import re

# 1. Model load
model = joblib.load("phishing_model.pkl")

# 2. Training dataset se feature names lo
df_train = pd.read_csv("Phishing_Legitimate_full.csv")
feature_names = df_train.drop(columns=["CLASS_LABEL"]).columns

# 3. Function: URL se features nikalna
def extract_features(url):
    parsed = urlparse(url)
    features = {}

    # Example features
    features["NumDots"] = url.count('.')
    features["SubdomainLevel"] = parsed.hostname.count('.') - 1 if parsed.hostname else 0
    features["PathLevel"] = parsed.path.count('/')
    features["UrlLength"] = len(url)
    features["NumDash"] = url.count('-')
    features["NumDashInHostname"] = parsed.hostname.count('-') if parsed.hostname else 0
    features["AtSymbol"] = 1 if '@' in url else 0
    features["TildeSymbol"] = 1 if '~' in url else 0
    features["NumUnderscore"] = url.count('_')
    features["NumPercent"] = url.count('%')
    features["NumQueryComponents"] = parsed.query.count('=') if parsed.query else 0
    features["NumAmpersand"] = url.count('&')
    features["NumHash"] = url.count('#')
    features["NumNumericChars"] = sum(c.isdigit() for c in url)
    features["NoHttps"] = 0 if parsed.scheme == 'https' else 1
    features["RandomString"] = 0
    features["IpAddress"] = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", parsed.hostname or "") else 0

    # Baaki features 0
    for col in feature_names:
        if col not in features:
            features[col] = 0

    return pd.DataFrame([features])

# 4. User se URL lena
url = input("Enter URL to check: ")

# 5. Predict
features_df = extract_features(url)
pred = model.predict(features_df)[0]

if pred == 1:
    print("🚨 Phishing Website Detected!")
else:
    print("✅ Safe Website")
