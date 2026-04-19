from altair import value
from numpy.ma import append
import streamlit as st
import pandas as pd
import joblib

# ---------------- LOAD MODEL ----------------
model = joblib.load("model.pkl")
features = joblib.load("features.pkl")

# Get feature importance
importances = model.feature_importances_

# Map feature → importance
feature_importance_map = dict(zip(features, importances))

# ------------------- EXPLANATION FUNCTION-------------------
def explain_prediction(input_df):
    explanations = []

    row = input_df.iloc[0].to_dict()

    sorted_features = sorted(
        feature_importance_map.items(),
        key=lambda x: x[1],
        reverse=True
    )

    for feature, importance in sorted_features[:5]:
        value = row.get(feature, 0)
        explanations.append((feature, value, importance))  # tuple

    return explanations

def interpret_feature(feature, value):
    explanations = {
        "SectionMinEntropy": "Low entropy may indicate normal code, high entropy may indicate obfuscation",
        "SizeOfImage": "Unusual image size may indicate packing or abnormal structure",
        "DllCharacteristics": "Certain flags may indicate suspicious execution behavior",
        "Subsystem": "Unexpected subsystem values can indicate non-standard execution",
        "Characteristics": "Binary characteristics flags may reveal suspicious properties",
        "DirectoryEntryImportSize": "High import count may indicate complex or suspicious behavior"
    }
    base = explanations.get(feature, "This feature contributes to the model decision")
    return f"{feature} = {value} → {base}"

#----------------DISPLAY FUNCTION-----------------
def display_results(df, pred, proba):
    
    st.subheader("📊 Risk Score")

    st.progress(float(proba))
    st.write(f"Malware Probability: {proba:.2f}")

    if proba > 0.8:
        st.error("🔴 HIGH RISK")
    elif proba > 0.5:
        st.warning("🟠 MEDIUM RISK")
    else:
        st.success("🟢 LOW RISK")



# ---------------- UI HEADER ----------------
st.set_page_config(page_title="Malware Detection System", layout="centered")

st.title("🛡️ Malware Detection System")
st.markdown("Analyze files using Machine Learning to detect malicious behavior")

mode = st.radio("Choose Input Method:", ["📂 Upload CSV", "✍️ Manual Input", "⚙️ EXE Analysis"])

# ---------------- CSV MODE ----------------
if mode == "📂 Upload CSV":
    uploaded_file = st.file_uploader("Upload feature dataset (.csv)")

    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        df = df.drop(['Name'], axis=1, errors='ignore')

        # Align features
        df = df.reindex(columns=features, fill_value=0)
        
        #row by row prediction
        for i in range(len(df)):
            row_df = df.iloc[[i]]

            pred = model.predict(row_df)[0]
            proba = model.predict_proba(row_df)[0][1]

            st.markdown(f"### File {i+1}")
            display_results(row_df, pred, proba)

        preds = model.predict(df)

        st.subheader("📊 Results")
        st.write(pd.DataFrame({"Prediction": preds}))

        st.success(f"Malicious Files: {sum(preds)} / {len(preds)}")

        # ---------------- EXPLANATION ----------------
        st.subheader("🧠 Explanation")

        explanations = explain_prediction(df)

        for feature, value, importance in explanations:
            st.write(
                f"• {interpret_feature(feature, value)} (importance: {importance:.3f})"
            )


# ---------------- MANUAL MODE ----------------
if mode == "✍️ Manual Input":
    st.subheader("Enter Feature Values")

    input_data = {}
    for feature in features:
        input_data[feature] = st.number_input(feature, value=0.0)

    if st.button("🔍 Predict"):
        df = pd.DataFrame([input_data])
        pred = model.predict(df)[0]
        proba = model.predict_proba(df)[0][1]

        display_results(df, pred, proba)

        # ---------------- EXPLANATION ----------------
        st.subheader("🧠 Explanation")

        explanations = explain_prediction(df)

        for feature, value, importance in explanations:
            st.write(
                f"• {interpret_feature(feature, value)} (importance: {importance:.3f})"
            )

        # ---------------- RESULT ----------------
        st.subheader("🔍 Final Result")

        if pred == 1:
            st.error("⚠ MALICIOUS FILE DETECTED")
        else:
            st.success("✔ FILE APPEARS SAFE")

#---------------- EXTRACT FUNCTION FOR EXE FILES ----------------
def extract_features(file):
    import pefile

    file_bytes = file.read()   # ✅ safer
    pe = pefile.PE(data=file_bytes)

    features_dict = {}   # ✅ correct dictionary

    # ---------------- OPTIONAL HEADER ----------------
    opt = pe.OPTIONAL_HEADER    

    features_dict['MajorLinkerVersion'] = opt.MajorLinkerVersion
    features_dict['MinorOperatingSystemVersion'] = opt.MinorOperatingSystemVersion
    features_dict['MajorSubsystemVersion'] = opt.MajorSubsystemVersion
    features_dict['MajorOperatingSystemVersion'] = opt.MajorOperatingSystemVersion
    features_dict['MinorImageVersion'] = opt.MinorImageVersion
    features_dict['SizeOfStackReserve'] = opt.SizeOfStackReserve
    features_dict['ImageBase'] = opt.ImageBase
    features_dict['Subsystem'] = opt.Subsystem
    features_dict['DllCharacteristics'] = opt.DllCharacteristics
    features_dict['SizeOfInitializedData'] = opt.SizeOfInitializedData
    features_dict['SizeOfHeaders'] = opt.SizeOfHeaders
    features_dict['MajorImageVersion'] = opt.MajorImageVersion
    features_dict['MinorSubsystemVersion'] = opt.MinorSubsystemVersion

    # ---------------- FILE HEADER ----------------
    features_dict['Characteristics'] = pe.FILE_HEADER.Characteristics

    # ---------------- DIRECTORY ENTRIES ----------------
    try:
        features_dict['DirectoryEntryExport'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    except:
        features_dict['DirectoryEntryExport'] = 0

    try:
        features_dict['DirectoryEntryImportSize'] = len(pe.DIRECTORY_ENTRY_IMPORT)
    except:
        features_dict['DirectoryEntryImportSize'] = 0

    try:
        features_dict['ImageDirectoryEntrySecurity'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
    except:
        features_dict['ImageDirectoryEntrySecurity'] = 0

    # ---------------- SECTION FEATURES ----------------
    entropies = []
    virtual_sizes = []
    characteristics = []

    for section in pe.sections:
        entropies.append(section.get_entropy())
        virtual_sizes.append(section.Misc_VirtualSize)
        characteristics.append(section.Characteristics)

    features_dict['SectionMinEntropy'] = min(entropies) if entropies else 0
    features_dict['SectionMinVirtualsize'] = min(virtual_sizes) if virtual_sizes else 0
    features_dict['SectionMaxChar'] = max(characteristics) if characteristics else 0

    return features_dict

#------------------ EXPLANATION ----------------
def explain_prediction(df):
    explanations = []

    for feature in features:
        value = df.iloc[0][feature]
        explanations.append(f"{feature} = {value} (Importance: {feature_importance_map.get(feature, 0):.4f})")

    return explanations

def interpret_feature(feature, value):
    explanations = {
        "SectionMinEntropy": "Low entropy may indicate normal code, high entropy may indicate obfuscation",
        "SizeOfImage": "Unusual image size may indicate packing or abnormal structure",
        "DllCharacteristics": "Certain flags may indicate suspicious execution behavior",
        "Subsystem": "Unexpected subsystem values can indicate non-standard execution",
        "Characteristics": "Binary characteristics flags may reveal suspicious properties",
        "DirectoryEntryImportSize": "High import count may indicate complex or suspicious behavior"
    }
    base = explanations.get(feature, "This feature contributes to the model decision")
    return f"{feature} = {value} → {base}"

#------------------ PDF GENERATION ----------------
def generate_pdf(pred, proba, explanations):
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet

    file_name = "report.pdf"
    doc = SimpleDocTemplate(file_name)
    styles = getSampleStyleSheet()

    content = []

    status = "MALICIOUS" if pred == 1 else "SAFE"

    content.append(Paragraph("Malware Analysis Report", styles['Title']))
    content.append(Spacer(1, 10))
    content.append(Paragraph(f"Prediction: {status}", styles['Normal']))
    content.append(Paragraph(f"Confidence: {proba:.2f}", styles['Normal']))
    content.append(Spacer(1, 10))

    content.append(Paragraph("Explanation:", styles['Heading2']))

    for exp in explanations:
        content.append(Paragraph(exp, styles['Normal']))

    doc.build(content)

    return file_name

# ---------------- EXE MODE ----------------
if mode == "⚙️ EXE Analysis":
    st.subheader("Upload Executable File (.exe)")

    exe_files = st.file_uploader(
        "Upload multiple .exe files",
        type=["exe"],
        accept_multiple_files=True
    )

    if exe_files:
        results = []
        all_predictions = []

        for file in exe_files:
            try:
                # ---------------- FEATURE EXTRACTION ----------------
                features_extracted = extract_features(file)

                df = pd.DataFrame([features_extracted])

                for col in features:
                    if col not in df:
                        df[col] = 0

                df = df[features]

                # ---------------- MODEL ----------------
                pred = model.predict(df)[0]
                proba = model.predict_proba(df)[0][1]

                explanations = explain_prediction(df)

                results.append({
                    "File": file.name,
                    "Prediction": "Malicious" if pred == 1 else "Safe",
                    "Confidence": round(proba, 2)
                })

                all_predictions.append(pred)

                # ---------------- PER-FILE DISPLAY ----------------
                st.markdown(f"---\n### 📄 {file.name}")

                st.subheader("📊 Risk Score")
                st.progress(float(proba))
                st.write(f"Malware Probability: {proba:.2f}")

                if proba > 0.8:
                    st.error("🔴 HIGH RISK")
                elif proba > 0.5:
                    st.warning("🟠 MEDIUM RISK")
                else:
                    st.success("🟢 LOW RISK")

                st.subheader("🧠 Explanation")

                for exp in explanations:
                    feature = exp.split("=")[0].strip()
                    value = df.iloc[0][feature]
                    st.write(f"• {interpret_feature(feature, value)}")

                # ---------------- PDF REPORT ----------------
                pdf_file = generate_pdf(pred, proba, explanations)

                with open(pdf_file, "rb") as f:
                    st.download_button(
                        f"📄 Download Report ({file.name})",
                        f,
                        file_name=f"{file.name}_report.pdf"
                    )

            except Exception as e:
                results.append({
                    "File": file.name,
                    "Prediction": "Error"
                })
                st.error(f"❌ Failed to analyze {file.name}")

        # ---------------- SUMMARY ----------------
        st.markdown("---")
        st.subheader("📊 Summary")

        df_results = pd.DataFrame(results)
        st.write(df_results)

        total = len(results)
        malicious = sum(1 for r in results if r["Prediction"] == "Malicious")

        st.metric("Total Files", total)
        st.metric("Malicious Detected", malicious)

        # ---------------- PIE CHART ----------------
        import matplotlib.pyplot as plt

        labels = ["Safe", "Malicious"]
        sizes = [total - malicious, malicious]

        fig, ax = plt.subplots()
        ax.pie(sizes, labels=labels, autopct='%1.1f%%')

        st.pyplot(fig)



# ---------------- FOOTER ----------------
st.markdown("---")
st.info("""
This system uses machine learning to detect malicious files based on extracted features.

Supported:
- CSV feature input  
- Manual feature entry  
- Basic EXE file analysis (experimental)

⚠ Note: EXE analysis is simplified and may not reflect full real-world detection accuracy.
""")