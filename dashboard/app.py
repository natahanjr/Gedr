"""
Streamlit dashboard for Gədr.

Pages:
  1. Scan (upload file or scan local path)
  2. Dashboard (projects, scores, severity breakdowns)
  3. Findings (detail view with AI remediation)

Run:  streamlit run dashboard/app.py
"""
import os
import sys
from pathlib import Path

# Ensure backend modules are importable when run from project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests  # noqa: E402
import streamlit as st  # noqa: E402

API_URL = os.getenv("CCI_API_URL", "http://127.0.0.1:8000")

st.set_page_config(page_title="Gədr", page_icon="🛡️", layout="wide")


def api_ok() -> bool:
    try:
        return requests.get(f"{API_URL}/api/health", timeout=3).ok
    except requests.RequestException:
        return False


def main():
    st.sidebar.title("🛡️ Gədr")
    st.sidebar.caption("AI-Assisted Multi-Language SAST")

    if not api_ok():
        st.sidebar.error(f"Backend unreachable at {API_URL}.\nRun: `uvicorn backend.api:app --port 8000`")
        return

    health = requests.get(f"{API_URL}/api/health", timeout=3).json()
    st.sidebar.write(f"**AI engine:** {'enabled' if health['ai_enabled'] else 'offline (no API key)'}")
    tools = [k for k, v in health["tools"].items() if v]
    st.sidebar.write(f"**External tools found:** {', '.join(tools) or 'none (heuristics active)'}")

    page = st.sidebar.radio("Navigation", ["Scan", "Dashboard", "Findings"])
    if page == "Scan":
        scan_page()
    elif page == "Dashboard":
        dashboard_page()
    else:
        findings_page()


# ----------------------------------------------------------------------
def scan_page():
    st.header("🔍 New Security Scan")
    st.write("Upload source code or point to a local project folder.")

    tab1, tab2 = st.tabs(["Upload file", "Scan local path"])

    with tab1:
        with st.form("upload_form"):
            uploaded = st.file_uploader(
                "Source file",
                type=["py", "java", "c", "cc", "cpp", "cxx", "h", "hpp",
                      "php", "js", "html", "css"],
            )
            use_ai = st.checkbox("Run Gədr AI analysis after scanning (requires API key)", value=False)
            submit = st.form_submit_button("Scan file")
        if submit and uploaded:
            with st.spinner("Scanning..."):
                r = requests.post(
                    f"{API_URL}/api/scan/upload",
                    files={"file": (uploaded.name, uploaded.getvalue())},
                    data={"use_ai": use_ai},
                    timeout=300,
                )
            _show_result(r)

    with tab2:
        with st.form("path_form"):
            path = st.text_input("Local directory or file path", value=r"F:\My Project\Gədr\sample_code")
            use_ai2 = st.checkbox("Run Gədr AI analysis after scanning (requires API key)", value=False)
            submit2 = st.form_submit_button("Scan path")
        if submit2 and path:
            with st.spinner("Scanning..."):
                r = requests.post(
                    f"{API_URL}/api/scan/project",
                    data={"path": path, "use_ai": use_ai2},
                    timeout=600,
                )
            _show_result(r)


def _show_result(r: requests.Response):
    if r.status_code != 200:
        st.error(f"Scan failed: {r.text}")
        return
    data = r.json()
    st.success(f"Scan complete — score {data['security_score']}/100 ({data['grade']})")
    st.write(data["summary"])
    st.json(
        {k: v for k, v in data.items() if k != "findings"},
        expanded=False,
    )


# ----------------------------------------------------------------------
def dashboard_page():
    st.header("📊 Dashboard")
    projects = requests.get(f"{API_URL}/api/projects", timeout=10).json()
    if not projects:
        st.info("No projects yet. Run a scan first.")
        return

    cols = st.columns(3)
    for i, pr in enumerate(projects[:3]):
        score = pr.get("last_score")
        with cols[i % 3]:
            st.metric(
                label=pr["name"],
                value=f"{score}/100" if score is not None else "—",
                delta=pr.get("last_scan", ""),
            )

    sel = st.selectbox("Select project", [p["name"] for p in projects], key="dash_proj")
    project = next(p for p in projects if p["name"] == sel)

    with st.expander("Project details"):
        st.json(project)

    scans = requests.get(f"{API_URL}/api/projects/{project['id']}", timeout=10).json().get("scans", [])
    if not scans:
        st.info("No scans for this project.")
        return

    scan_id = st.selectbox("Select scan", [s["id"] for s in scans], key="dash_scan")
    data = requests.get(f"{API_URL}/api/scans/{scan_id}", timeout=10).json()

    st.subheader("Severity breakdown")
    brk = data["severity_breakdown"]
    st.bar_chart(brk)

    st.subheader("Findings overview")
    for f in data["findings"]:
        st.markdown(
            f"- **[{f['severity']}]** {f['title']} — `{f['file']}:{f['line']}` "
            f"({f['cwe']}, {f['owasp']})"
        )


# ----------------------------------------------------------------------
def findings_page():
    st.header("🧾 Findings & AI Remediation")
    projects = requests.get(f"{API_URL}/api/projects", timeout=10).json()
    if not projects:
        st.info("No projects yet.")
        return

    sel = st.selectbox("Project", [p["name"] for p in projects], key="find_proj")
    project = next(p for p in projects if p["name"] == sel)
    scans = requests.get(f"{API_URL}/api/projects/{project['id']}", timeout=10).json().get("scans", [])
    if not scans:
        return

    scan_id = st.selectbox("Scan", [s["id"] for s in scans], key="find_scan")
    data = requests.get(f"{API_URL}/api/scans/{scan_id}", timeout=10).json()

    severity_filter = st.multiselect("Filter severity", ["Critical", "High", "Medium", "Low"], default=["Critical", "High"])
    findings = [f for f in data["findings"] if f["severity"] in severity_filter]

    if not findings:
        st.success("No findings match the filter.")
        return

    for f in findings:
        with st.expander(f"[{f['severity']}] {f['title']} — {f['file']}:{f['line']}"):
            st.markdown(f"**Scanner:** {f['scanner']} | **CWE:** {f['cwe']} | **OWASP:** {f['owasp']}")
            st.code(f["code"] or "", language="text")
            rec = f.get("ai_recommendation")
            if rec:
                st.markdown(f"### 🤖 AI Analysis")
                st.markdown(f"**Explanation:** {rec['explanation']}")
                st.markdown(f"**Security impact:** {rec['impact']}")
                st.markdown(f"**Attack scenario:** {rec['attack_scenario']}")
                st.markdown(f"**Root cause:** {rec['root_cause']}")
                st.markdown(f"**Recommended fix:** {rec['recommended_fix']}")
                st.code(rec.get("secure_code") or "", language="text")
                st.caption(f"Model: {rec.get('model')}")
            else:
                st.warning("No AI analysis yet. Set GEMINI_API_KEY (or CCI_AI_API_KEY) in .env and use the API endpoint to generate one.")
            st.markdown(
                f"[Download full report]({API_URL}/api/scans/{scan_id}/report) (PDF)",
                unsafe_allow_html=True,
            )

    st.download_button(
        "Download PDF report",
        data=requests.get(f"{API_URL}/api/scans/{scan_id}/report", timeout=30).content,
        file_name=f"cybercode_report_{scan_id}.pdf",
        mime="application/pdf",
    )


if __name__ == "__main__":
    main()
