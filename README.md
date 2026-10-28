# 🛡️ AI Phishing URL Detector

A simple Streamlit app that checks a website link and tells you whether it looks like **phishing**. It combines simple Python rules with **Google Gemini Flash**.

## How it works
1. **Rule-based check (Python):** reads the URL text and looks for warning signs, such as a raw IP address, an `@` trick, look-alike (punycode) domains, link shorteners, odd endings like `.xyz`, a brand name inside a fake domain, and "urgent account" words. It gives a risk score from 0 to 100.
2. **AI check (Gemini):** receives the URL and the findings, then returns a verdict (**SAFE**, **SUSPICIOUS** or **PHISHING**), a confidence level, reasons and safety advice.

If the AI is unavailable, the app clearly says so and still shows the rule-based result. It never invents an AI answer.

## Important safety notes
- The app **never opens or visits** the URL. It only reads the text.
- It cannot see the real website, so it can make mistakes. A "safe" result is **not a guarantee**.
- For extra confidence, also check links with Google Safe Browsing or VirusTotal.
- Never type passwords on a page you do not trust.

## Files
```
app.py            # The whole application
requirements.txt  # Python packages
README.md         # This file
```

## Run on your computer
1. Install Python 3.10 or newer.
2. Get a free Gemini API key: https://aistudio.google.com/apikey
3. Give the app the key (never write it inside the code):
   - Create the file `.streamlit/secrets.toml` with this line:
     ```toml
     GEMINI_API_KEY = "your-key-here"
     ```
   - or set an environment variable named `GEMINI_API_KEY`.
4. Install and run:
   ```bash
   pip install -r requirements.txt
   streamlit run app.py
   ```

## Push to GitHub (website only)
1. Sign in at https://github.com, click **+** then **New repository**.
2. Name it (for example `ai-phishing-url-detector`), choose **Public**, and click **Create repository**.
3. Click **uploading an existing file**, drag in `app.py`, `requirements.txt` and `README.md`, then click **Commit changes**.

Never upload your API key or a `secrets.toml` file.

## Deploy on Streamlit Community Cloud
1. Go to https://share.streamlit.io and sign in with GitHub.
2. Click **Create app**, choose your repository, branch `main`, and main file `app.py`.
3. Open **Advanced settings → Secrets** and paste:
   ```toml
   GEMINI_API_KEY = "your-key-here"
   ```
4. Click **Deploy**. After a few minutes you get a public link.

## Limits
- Each browser session can run 20 checks per hour to protect the free Gemini quota.
- Model names change over time. If you see "model not found", edit `PRIMARY_MODEL` and `FALLBACK_MODEL` at the top of `app.py`.

## Troubleshooting
| Problem | Fix |
|---|---|
| "AI is not configured" | Add `GEMINI_API_KEY` to Secrets (or the environment) |
| "Gemini rejected the request" | The API key is wrong or not enabled |
| "Gemini is busy" | Temporary. Wait a minute and try again |
| `ModuleNotFoundError` on deploy | Check that `requirements.txt` lists `streamlit` and `google-genai` |
