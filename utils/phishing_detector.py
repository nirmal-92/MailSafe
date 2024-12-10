import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
import validators

# Download NLTK data
nltk.download("punkt")
nltk.download("stopwords")

def analyze_email(email_content):
    """
    Analyze email content for phishing indicators.
    """
    # Keywords indicative of phishing
    phishing_keywords = ["urgent", "verify", "suspend", "password", "login", "click here", "account"]
    suspicious_urls = []
    score = 0

    # Tokenize and remove stopwords
    tokens = word_tokenize(email_content.lower())
    filtered_tokens = [word for word in tokens if word.isalnum()]
    stop_words = set(stopwords.words("english"))
    significant_words = [word for word in filtered_tokens if word not in stop_words]

    # Check for phishing keywords
    for word in significant_words:
        if word in phishing_keywords:
            score += 1

    # Check for URLs
    for word in tokens:
        if validators.url(word):
            suspicious_urls.append(word)

    # Analyze score
    strength = "Safe"
    if score >= 3 or suspicious_urls:
        strength = "Suspicious"
    if score >= 5:
        strength = "Phishing"

    # Results
    result = {
        "strength": strength,
        "score": score,
        "keywords": phishing_keywords,
        "suspicious_urls": suspicious_urls,
    }
    return result
