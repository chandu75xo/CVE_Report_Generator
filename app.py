import streamlit as st
import os
import tempfile
from script2 import process_url, get_urls

st.set_page_config(page_title="Multi-Source CVE Scanner", layout="wide")
st.title("🔎 Multi-Source CVE Scanner")
st.write("Scan a single URL or upload a .txt file with URLs to check for the Top 10 vulnerabilities from multiple public sources.")

# Input widgets
url_input = st.text_input("Enter a single URL (e.g., http://testphp.vulnweb.com/)")
file_input = st.file_uploader("Or upload a .txt file with URLs (one per line)", type=["txt"])

run_scan = st.button("Scan for Vulnerabilities")

results = []
if run_scan:
    urls = []
    if url_input:
        urls = [url_input.strip()]
    elif file_input:
        # Save uploaded file to a temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp:
            tmp.write(file_input.read())
            tmp_path = tmp.name
        urls = get_urls(tmp_path)
        os.unlink(tmp_path)
    else:
        st.warning("Please enter a URL or upload a .txt file.")
    if urls:
        st.info(f"Scanning {len(urls)} URL(s)... This may take a while.")
        for idx, url in enumerate(urls):
            with st.spinner(f"Scanning {url}..."):
                result, status = process_url(url, idx+1)
                results.append(result)
        for result in results:
            st.markdown(f"### Results for: `{result['url']}`")
            st.write(f"**IP:** {result['ip']}")
            st.write(f"**Open Ports:** {result['open_ports']}")
            st.write(f"**Software:** {result['software']}")
            st.write(f"**Version:** {result['version']}")
            st.write("---")
            st.write("#### Top 10 Unique CVEs:")
            if result['all_cves']:
                for cve_id, desc in result['all_cves'][:10]:
                    st.write(f"- **{cve_id}**: {desc}")
            else:
                st.write("No unique CVEs found.")
            st.write("---") 