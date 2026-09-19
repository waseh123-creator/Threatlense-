
import os
import json
import ipaddress
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import streamlit as st
from dotenv import load_dotenv
from google import genai

from sources import SOURCES

# ============================================================
# CONFIG & PAGE CONFIG
# ============================================================

load_dotenv()

st.set_page_config(
    page_title="ThreatLens",
    page_icon="🛡️",
    layout="wide"
)

# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:
    st.title("Settings")
    vt_api_key_input = st.text_input("VirusTotal API key", type="password")
    gemini_api_key_input = st.text_input("Gemini API key", type="password")

    st.markdown("---")
    st.markdown("**Active intelligence sources**")
    st.checkbox("VirusTotal", value=True, disabled=True)
    st.checkbox("WHOIS", value=True, disabled=True)

# Key resolution
VIRUSTOTAL_API_KEY = vt_api_key_input.strip() or os.getenv("VIRUSTOTAL_API_KEY", "")
GEMINI_API_KEY = gemini_api_key_input.strip() or os.getenv("GEMINI_API_KEY", "")

if VIRUSTOTAL_API_KEY:
    os.environ["VIRUSTOTAL_API_KEY"] = VIRUSTOTAL_API_KEY

client = None
if GEMINI_API_KEY:
    try:
        client = genai.Client(api_key=GEMINI_API_KEY)
    except Exception:
        client = None

# ============================================================
# SESSION STATE
# ============================================================

if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None

# ============================================================
# VALIDATION
# ============================================================

def validate_target(target_type, target):
    target = target.strip()

    if not target:
        return False, "Target cannot be empty."

    if len(target) > 2048:
        return False, "Target is too long."

    if target_type == "IP":
        try:
            ipaddress.ip_address(target)
            return True, ""
        except ValueError:
            return False, "Invalid IP address."

    if target_type == "Domain":
        domain = target.lower().strip(".")
        try:
            domain = domain.encode("idna").decode("ascii")
        except UnicodeError:
            return False, "Invalid domain."

        if (
            len(domain) > 253
            or "." not in domain
            or domain.startswith(".")
            or domain.endswith(".")
        ):
            return False, "Invalid domain."

        labels = domain.split(".")
        for label in labels:
            if (
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
            ):
                return False, "Invalid domain."

        return True, ""

    if target_type == "URL":
        try:
            parsed = urlparse(target)
            if parsed.scheme not in ("http", "https"):
                return False, "URL must use http or https."
            if not parsed.hostname:
                return False, "URL must contain a valid hostname."
            return True, ""
        except Exception:
            return False, "Invalid URL."

    return False, "Unsupported target type."

# ============================================================
# SOURCE EXECUTION
# ============================================================

def run_source(source_name, source_function, target_type, target):
    try:
        return source_name, source_function(target_type, target)
    except Exception as e:
        return source_name, {
            "source": source_name,
            "status": "error",
            "error": str(e)
        }

def run_all_sources(target_type, target):
    results = {}
    with ThreadPoolExecutor(max_workers=len(SOURCES)) as executor:
        futures = {
            executor.submit(
                run_source,
                name,
                function,
                target_type,
                target
            ): name
            for name, function in SOURCES.items()
        }
        for future in as_completed(futures):
            source_name, result = future.result()
            results[source_name] = result
    return results

# ============================================================
# BASELINE HEURISTIC
# ============================================================

def baseline_verdict(results):
    vt = results.get("VirusTotal", {})
    if vt.get("status") != "success":
        return "Unknown"

    data = vt.get("data", {})
    stats = data.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0) or 0
    suspicious = stats.get("suspicious", 0) or 0

    if malicious > 0:
        return "Malicious"
    if suspicious > 0:
        return "Suspicious"

    return "Safe"

# ============================================================
# GEMINI ANALYSIS
# ============================================================

def analyze_with_gemini(
    target_type,
    target,
    results,
    knowledge_level,
    baseline
):
    if not client:
        return {
            "verdict": baseline,
            "confidence": 0,
            "summary": "Gemini API key missing or invalid.",
            "key_findings": [
                "Please enter a valid Gemini API key in the sidebar."
            ],
            "recommendation": "Check API keys in Settings.",
            "limitations": ["AI analysis unavailable without valid API key."]
        }

    prompt = f"""
You are a cybersecurity analyst explaining results to a user.

Target type: {target_type}
Target: {target}
Knowledge level: {knowledge_level}
Baseline heuristic verdict: {baseline}

Source results:
{json.dumps(results, indent=2, default=str)}

Analyze the available evidence.

IMPORTANT:
- Do not claim that absence of detections proves safety.
- Clearly distinguish evidence from assumptions.
- If data is incomplete, say so.
- Explain technical findings according to the requested knowledge level.

Return ONLY valid JSON using exactly this structure:
{{
    "verdict": "Safe | Suspicious | Malicious | Unknown",
    "confidence": 0,
    "summary": "short explanation",
    "key_findings": [
        "finding 1",
        "finding 2"
    ],
    "recommendation": "practical recommendation",
    "limitations": [
        "limitation 1",
        "limitation 2"
    ]
}}

Confidence must be an integer from 0 to 100.
"""

    # Try available models sequentially.
    # NOTE: Google retired the 2.0/2.5 Flash line for new users - the API
    # now tells callers to use the 3.x models below. Model names change
    # over time; if these ever 404 again, call client.models.list() to
    # see exactly what your API key currently supports and update this
    # list accordingly.
    models_to_try = [
        "gemini-3.6-flash",
        "gemini-3.5-flash-lite",
        "gemini-3.5-flash",
    ]

    last_errors = []

    for model_name in models_to_try:
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=prompt
            )

            text = response.text.strip()

            if text.startswith("```"):
                text = text.replace("```json", "").replace("```", "").strip()

            return json.loads(text)

        except Exception as e:
            last_errors.append(f"{model_name}: {e}")
            continue

    combined_error = " | ".join(last_errors) if last_errors else "Unknown error"

    return {
        "verdict": baseline,
        "confidence": 0,
        "summary": f"Gemini Error: {combined_error}",
        "key_findings": [],
        "recommendation": "Verify Gemini API key and model availability.",
        "limitations": ["Gemini analysis failed across all attempted models."],
        "error": combined_error
    }

# ============================================================
# MAIN UI
# ============================================================

st.title("🛡️ ThreatLens")
st.markdown(
    "Check an **IP address, domain, or URL** using VirusTotal and WHOIS, "
    "then get a Gemini-powered cybersecurity interpretation."
)

st.divider()

col1, col2 = st.columns([1, 2])

with col1:
    target_type = st.selectbox(
        "Target Type",
        ["IP", "Domain", "URL"]
    )

with col2:
    target = st.text_input(
        "Target",
        placeholder={
            "IP": "8.8.8.8",
            "Domain": "example.com",
            "URL": "https://example.com"
        }[target_type]
    )

knowledge_level = st.select_slider(
    "Knowledge Level",
    options=["Beginner", "Intermediate", "Expert"],
    value="Beginner"
)

analyze_button = st.button(
    "🔍 Analyze Target",
    type="primary",
    use_container_width=True
)

# ============================================================
# ANALYSIS EXECUTION
# ============================================================

if analyze_button:
    valid, error_message = validate_target(target_type, target)

    if not valid:
        st.error(error_message)
    else:
        with st.spinner("Checking security sources..."):
            source_results = run_all_sources(target_type, target)
            baseline = baseline_verdict(source_results)
            ai_result = analyze_with_gemini(
                target_type,
                target,
                source_results,
                knowledge_level,
                baseline
            )

            st.session_state.analysis_result = {
                "target_type": target_type,
                "target": target,
                "sources": source_results,
                "baseline": baseline,
                "ai": ai_result
            }

# ============================================================
# DISPLAY RESULTS
# ============================================================

result = st.session_state.analysis_result

if result:
    st.divider()
    st.subheader("Analysis Result")

    ai = result["ai"]
    verdict = ai.get("verdict", result["baseline"])
    confidence = ai.get("confidence", 0)

    if verdict == "Safe":
        st.success(f"🟢 VERDICT: {verdict}")
    elif verdict == "Suspicious":
        st.warning(f"🟠 VERDICT: {verdict}")
    elif verdict == "Malicious":
        st.error(f"🔴 VERDICT: {verdict}")
    else:
        st.info(f"⚪ VERDICT: {verdict}")

    st.metric("Confidence", f"{confidence}%")

    st.subheader("🤖 AI Insight")
    st.write(ai.get("summary", "No summary available."))

    findings = ai.get("key_findings", [])
    if findings:
        st.subheader("Key Findings")
        for finding in findings:
            st.write(f"• {finding}")

    st.subheader("Recommendation")
    st.write(ai.get("recommendation", "No recommendation available."))

    limitations = ai.get("limitations", [])
    if limitations:
        with st.expander("Limitations"):
            for limitation in limitations:
                st.write(f"• {limitation}")

    st.subheader("Source Results")
    for source_name, source_result in result["sources"].items():
        with st.expander(source_name):
            st.json(source_result)
