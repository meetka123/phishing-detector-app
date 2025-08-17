import tkinter as tk
import pandas as pd
import joblib

# Model load
model = joblib.load("phishing_model.pkl")
df_train = pd.read_csv("Phishing_Legitimate_full.csv")
feature_names = df_train.drop(columns=["CLASS_LABEL"]).columns

# Function
def check_url():
    url = entry.get()
    example_features = {col: 0 for col in feature_names}  # abhi ke liye dummy
    df_test = pd.DataFrame([example_features], columns=feature_names)
    pred = model.predict(df_test)[0]
    if pred == 1:
        result_label.config(text="🚨 Phishing Website Detected!", fg="red")
    else:
        result_label.config(text="✅ Safe Website", fg="green")

# GUI
root = tk.Tk()
root.title("Phishing Detection App")

tk.Label(root, text="Enter URL:").pack()
entry = tk.Entry(root, width=50)
entry.pack()

tk.Button(root, text="Check", command=check_url).pack()
result_label = tk.Label(root, text="")
result_label.pack()

root.mainloop()
