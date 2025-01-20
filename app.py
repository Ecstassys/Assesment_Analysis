from flask import Flask, render_template, request, redirect, url_for
import os
import requests
from bs4 import BeautifulSoup
import matplotlib.pyplot as plt

app = Flask(__name__)

# Initialize a dictionary to store results
results_summary = {
    "Security Headers Missing": 0,
    "SQL Injection Vulnerabilities": 0,
    "XSS Vulnerabilities": 0,
    "Exposed Files/Directories": 0
}

# Define vulnerability assessment functions
def check_security_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers
        security_headers = {
            "Content-Security-Policy": "Content Security Policy",
            "X-XSS-Protection": "XSS Protection",
            "X-Frame-Options": "Frame Options",
            "X-Content-Type-Options": "Content Type Options",
            "Strict-Transport-Security": "HSTS (HTTPS Strict Transport Security)"
        }
        missing_headers = sum(1 for header in security_headers if header not in headers)
        results_summary["Security Headers Missing"] += missing_headers
    except Exception as e:
        print(f"[!] Error checking security headers: {e}")

def sql_injection_test(url):
    try:
        response = requests.get(url + "' OR '1'='1")
        if "sql" in response.text.lower() or "error" in response.text.lower():
            results_summary["SQL Injection Vulnerabilities"] += 1
    except Exception as e:
        print(f"[!] Error performing SQL injection test: {e}")

def xss_test(url):
    try:
        response = requests.get(url + "<script>alert('XSS')</script>")
        if "<script>alert('XSS')</script>" in response.text:
            results_summary["XSS Vulnerabilities"] += 1
    except Exception as e:
        print(f"[!] Error performing XSS test: {e}")

def scan_exposed_files(url):
    common_files = ["robots.txt", ".env", "config.php", "admin", "backup", "phpinfo.php"]
    for file in common_files:
        try:
            response = requests.get(f"{url}/{file}")
            if response.status_code == 200:
                results_summary["Exposed Files/Directories"] += 1
        except Exception as e:
            print(f"[!] Error checking exposed files: {e}")

def vulnerability_assessment(url):
    # Reset results
    for key in results_summary:
        results_summary[key] = 0

    # Perform assessments
    if url.startswith("http"):
        check_security_headers(url)
        sql_injection_test(url)
        xss_test(url)
        scan_exposed_files(url)

def generate_plot():
    categories = list(results_summary.keys())
    values = list(results_summary.values())

    plt.figure(figsize=(10, 6))
    plt.bar(categories, values, color=['red', 'orange', 'yellow', 'blue'])
    plt.title("Vulnerability Assessment Results", fontsize=16)
    plt.xlabel("Vulnerability Types", fontsize=12)
    plt.ylabel("Number of Issues Found", fontsize=12)
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()

    # Ensure 'static' directory exists
    static_dir = "static"
    if not os.path.exists(static_dir):
        os.makedirs(static_dir)

    plt.savefig("static/results_plot.png")
    plt.close()

# Define Flask routes
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("url")
        if url:
            vulnerability_assessment(url)
            generate_plot()
            return redirect(url_for("results"))
    return render_template("index.html")

@app.route("/results")
def results():
    return render_template("results.html", results=results_summary, plot_url="static/results_plot.png")

if __name__ == "__main__":
    app.run(debug=True)
