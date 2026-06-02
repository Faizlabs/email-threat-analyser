# Email Threat Analyzer

This is a client-side web application that scans emails, text, and URLs for common cybersecurity threats. It uses a regex engine with over 25 detection rules to spot phishing attempts, credential lures, unsafe links, financial scams, and suspicious language patterns.

## Features

* Scans text against rules categorized into urgency, credential phishing, unsafe URLs, financial scams, attachment threats, social engineering, impersonation, and technical indicators.
* Extracts URLs from input text and evaluates them for risks like HTTP vs HTTPS, IP-based URLs, suspicious TLDs, and URL shorteners.
* Calculates a threat score from 0 to 100% and gives a verdict.
* Provides a detailed breakdown of why a text was flagged, highlighting the matched phrases and giving advice.
* Keeps scan history locally using localStorage and allows exporting scan results as JSON.
* Adjustable detection sensitivity to reduce false positives.

## Tech Stack

The project is built with plain HTML, CSS, and vanilla JavaScript. There are no build tools or backend servers required. It uses Lucide Icons for the UI.

## How to use

1. Clone or download this repository.
2. Open index.html in your browser.
3. Paste an email, email headers, or a URL into the input area and click Analyze Threat.
4. Check the threat score and the detailed breakdown of flagged rules.

## Privacy

Everything runs completely locally in your browser. No data or text is sent to any external servers. Your scan history is saved locally in your browser's localStorage, which you can clear from the settings tab.

## Disclaimer

This tool is for educational purposes. It uses static pattern matching to identify common phishing tropes. It does not use live threat feeds or sandboxing. It is not a replacement for real email security gateways or antivirus software. Always be careful and verify suspicious emails through official channels.
