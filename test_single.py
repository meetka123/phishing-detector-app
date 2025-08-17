import pandas as pd
import joblib

# Model load
model = joblib.load("phishing_model.pkl")

# Training data se exact feature names le lo
df_train = pd.read_csv("Phishing_Legitimate_full.csv")
feature_names = df_train.drop(columns=["CLASS_LABEL"]).columns

# Example features dict (sab zero)
example_features = {col: 0 for col in feature_names}

# DataFrame banate waqt columns ka order training wale se match karo
df_test = pd.DataFrame([example_features], columns=feature_names)

# Predict
pred = model.predict(df_test)[0]
if pred == 1:
    print("🚨 Phishing Website Detected!")
else:
    print("✅ Safe Website")
