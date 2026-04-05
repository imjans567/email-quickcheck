import streamlit as st
import pandas as pd
import joblib
import numpy as np

# -------------------------------
# Page Config
# -------------------------------
st.set_page_config(page_title="Malware Detector", page_icon="🛡", layout="wide")

# -------------------------------
# Custom Styling
# -------------------------------
st.markdown("""
    <style>
    body {
        background-color: #0e1117;
        color: white;
    }
    .stApp {
        background: linear-gradient(135deg, #0e1117, #1f2937);
    }
    h1 {
        color: #4CAF50;
        text-align: center;
    }
    .stButton>button {
        background-color: #4CAF50;
        color: white;
        border-radius: 10px;
        padding: 10px;
    }
    .stFileUploader {
        border: 2px dashed #4CAF50;
        padding: 10px;
        border-radius: 10px;
    }
    </style>
""", unsafe_allow_html=True)

# -------------------------------
# Load model
# -------------------------------
model = joblib.load("model.pkl")
features = joblib.load("features.pkl")

# -------------------------------
# Header
# -------------------------------
st.markdown("## 🛡 Malware Detection Dashboard")
st.markdown("---")
st.info("Upload a dataset to analyze potential threats")

# -------------------------------
# Upload
# -------------------------------
uploaded_file = st.file_uploader("📂 Upload your dataset (CSV)", type=["csv"])

if uploaded_file:

    df = pd.read_csv(uploaded_file)

    st.subheader("📊 Data Preview")
    st.dataframe(df.head())

    # -------------------------------
    # Preprocessing
    # -------------------------------
    df = df.drop(['Name'], axis=1, errors='ignore')

    # Feature check
    missing_features = [f for f in features if f not in df.columns]

    if missing_features:
        st.error(f"❌ Missing Features: {missing_features}")
        st.stop()

    df = df[features]

    st.success("✅ Data ready for prediction")

        # -------------------------------
    # Prediction
    # -------------------------------
    predictions = model.predict(df)

    try:
        probs = model.predict_proba(df)
        confidence = np.max(probs, axis=1)
    except:
        confidence = [None] * len(predictions)

    # -------------------------------
    # Build Results
    # -------------------------------
    results = []

    for i in range(len(predictions)):
        label = "🔴 Malicious" if predictions[i] == 1 else "🟢 Benign"
        conf = f"{confidence[i]*100:.2f}%" if confidence[i] is not None else "N/A"

        results.append({
            "File": i+1,
            "Prediction": label,
            "Confidence": conf
        })

    results_df = pd.DataFrame(results)

    # -------------------------------
    # Results Table
    # -------------------------------
    st.subheader("🔍 Prediction Results")
    st.dataframe(results_df)

    # -------------------------------
    # Highlight Results
    # -------------------------------
    for i in range(len(results)):
        if predictions[i] == 1:
            st.error(f"File {i+1}: MALICIOUS ⚠️ | Confidence: {results[i]['Confidence']}")
        else:
            st.success(f"File {i+1}: SAFE ✅ | Confidence: {results[i]['Confidence']}")

    # -------------------------------
    # Metrics
    # -------------------------------
    benign_count = int((predictions == 0).sum())
    malicious_count = int((predictions == 1).sum())

    col1, col2 = st.columns(2)
    col1.metric("🟢 Benign Files", benign_count)
    col2.metric("🔴 Malicious Files", malicious_count)

    # -------------------------------
    # Warning Message
    # -------------------------------
    if malicious_count > 0:
        st.warning("⚠ Malicious files detected!")
    else:
        st.success("✅ All files appear safe.")

    # -------------------------------
    # Download Results
    # -------------------------------
    csv = results_df.to_csv(index=False).encode('utf-8')
    st.download_button(
        "📥 Download Results",
        csv,
        "predictions.csv",
        "text/csv"
    )
    # --------------------------------
    # Footer
    # --------------------------------
    st.markdown("---")
    st.markdown("🔐 Built for Malware Detection | ML-powered security tool")