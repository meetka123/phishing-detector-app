import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import xgboost as xgb
import joblib

# 1. Dataset load
df = pd.read_csv("Phishing_Legitimate_full.csv")

# 2. Features aur Target alag karo
X = df.drop(columns=["CLASS_LABEL"])
y = df["CLASS_LABEL"]

# 3. Train-Test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# 4. Model define karo (XGBoost)
model = xgb.XGBClassifier(
    n_estimators=200,
    max_depth=8,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    use_label_encoder=False,
    eval_metric="logloss"
)

# 5. Train karo
model.fit(X_train, y_train)

# 6. Prediction
y_pred = model.predict(X_test)

# 7. Accuracy print karo
print("✅ Model Training Complete")
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# 8. Model save karo
joblib.dump(model, "phishing_model.pkl")
print("🎉 Model saved as phishing_model.pkl")
