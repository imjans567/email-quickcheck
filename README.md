# 🛡 Malware Detection using Machine Learning

## 📌 Overview

This project detects whether a file is **malicious or benign** using machine learning.

It uses extracted PE file features and applies trained models to classify files.

---

## 🚀 Features

* Upload CSV dataset
* Detect malicious files
* Confidence score for predictions
* Clean UI using Streamlit
* Feature validation to avoid mismatch errors

---

## 🧠 Models Used

* Logistic Regression (baseline)
* Random Forest (final model)
* XGBoost (comparison)

## 📊 Model Evaluation and Results

### 🔍 Overview

Multiple models were evaluated to determine the most effective approach for malicious attachment detection. Experiments were conducted using:

* Full feature set (after removing constant and non-informative features)
* Reduced feature set (Top 20 features based on importance)

Models evaluated:

* Logistic Regression (Baseline)
* Random Forest
* XGBoost

---

## 📈 Performance Comparison

| Model               | Features Used | Accuracy | Recall (Malware) | False Negatives |
| ------------------- | ------------- | -------- | ---------------- | --------------- |
| Logistic Regression | All Features  | 0.96     | 0.98             | 72              |
| Logistic Regression | Top 20        | 0.96     | 0.97             | 74              |
| Random Forest       | All Features  | 0.99     | 1.00             | 13              |
| Random Forest       | Top 20        | 0.99     | 1.00             | 9               |
| XGBoost             | All Features  | 0.99     | 1.00             | 8               |
| XGBoost             | Top 20        | 0.99     | 1.00             | 4               |

---

## 🚨 Confusion Matrix Insights

### 🔹 Logistic Regression (All Features)

* False Negatives: 72
* Higher number of missed malware samples
* Not suitable for high-security applications

### 🔹 Random Forest (Top 20 Features)

* False Negatives: 9
* Strong detection capability
* Efficient with reduced feature set

### 🔹 XGBoost (Top 20 Features)

* False Negatives: 4 (Best)
* Lowest number of missed threats
* Maintains high precision and recall

---

## 🎯 Key Findings

### 1. Feature Reduction Effect

Reducing features from the full set to the top 20:

* Did not significantly impact performance
* Improved model efficiency
* Demonstrated that only a subset of features carries most predictive power

---

### 2. Model Comparison

* Logistic Regression performed well but missed a significant number of malicious samples
* Random Forest significantly improved detection performance
* XGBoost achieved the best overall performance with the lowest false negatives

---

### 3. Security Perspective

In malware detection systems, minimizing false negatives is critical.

* Logistic Regression → higher risk (missed malware)
* Random Forest → strong performance
* XGBoost → best detection capability

---

## 🏆 Final Model Selection

**XGBoost with Top 20 Features** was selected as the final model because:

* Highest detection rate
* Lowest false negatives (4)
* Efficient feature usage
* Strong generalization performance

---

## 🚀 Summary

The project demonstrates that:

* Tree-based models outperform linear models in malware detection tasks
* Feature selection can significantly reduce complexity without sacrificing performance
* XGBoost provides the most reliable detection with minimal missed threats

This makes the model suitable for real-world cybersecurity applications where accurate threat detection is critical.


---

## 📊 Results

* Accuracy: ~99%
* High recall for malware detection
* Very low false negatives

---

## 🖥 How to Run

```bash
git clone https://github.com/imjans567/email-quickcheck.git
cd email-quickcheck

python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt
python -m streamlit run app_ui.py
```

---

## 📂 Project Structure

```
app_ui.py        # Streamlit UI
model.pkl        # Trained model
features.pkl     # Selected features
requirements.txt # Dependencies
```

---

## 🌍 Future Improvements

* Deploy as web application
* Add explainability (SHAP)
* Integrate FastAPI backend

---

## Website Screenshots



## 👩‍💻 Author

Janani Mihiravi Arambegedara 

