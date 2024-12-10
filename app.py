from flask import Flask, render_template, request
from utils.phishing_detector import analyze_email

app = Flask(__name__)
app.secret_key = "your_secret_key"

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        email_content = request.form.get("email_content")
        result = analyze_email(email_content)
        return render_template("result.html", result=result)
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
