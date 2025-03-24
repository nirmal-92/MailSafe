from flask import Flask, render_template, request
import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
import validators

app = Flask(__name__)

# Download necessary NLTK data
nltk.download("punkt", quiet=True)
nltk.download("stopwords", quiet=True)

# Function to analyze email content
def analyze_email(email_content):
    phishing_keywords = [
        "urgent", "verify", "suspend", "password", "login", "click here",
        "account", "update", "security", "credit card", "bank", "alert",
        "payment", "confirm", "winning", "lottery", "prize", "hacked", "refund"
    ]
    suspicious_urls = []
    score = 0

    # Tokenize and clean email content
    tokens = word_tokenize(email_content.lower())
    filtered_tokens = [word for word in tokens if word.isalnum()]
    stop_words = set(stopwords.words("english"))
    significant_words = [word for word in filtered_tokens if word not in stop_words]

    # Check for phishing keywords
    matched_keywords = [word for word in significant_words if word in phishing_keywords]
    score += len(matched_keywords)

    # Detect suspicious URLs
    for word in tokens:
        if validators.url(word):
            suspicious_urls.append(word)

    # Determine risk level
    if score >= 5 or suspicious_urls:
        risk_level = "Phishing Email 🚨"
    elif score >= 3:
        risk_level = "Suspicious Email ⚠️"
    else:
        risk_level = "Safe Email ✅"

    return risk_level, score, matched_keywords, suspicious_urls

# Route for the main page
@app.route("/")
def index():
    return render_template("index.html")

# Route to analyze email and display results
@app.route("/analyze", methods=["POST"])
def analyze():
    email_content = request.form.get("email_content", "")

    if not email_content:
        return render_template("result.html", risk_level="N/A", score=0, matched_keywords=[], suspicious_urls=[],
                               error="Email content is required!")

    risk_level, score, matched_keywords, suspicious_urls = analyze_email(email_content)

    return render_template(
        "result.html",
        risk_level=risk_level,
        score=score,
        matched_keywords=matched_keywords,
        suspicious_urls=suspicious_urls
    )

if __name__ == "__main__":
    app.run(debug=True)
