# AgentShield starter prototype

## Run locally (Windows)
1. Install Python 3.11+ from https://www.python.org/downloads/ and enable **Add Python to PATH**.
2. Extract this ZIP into a folder.
3. Open PowerShell in that folder.
4. Run:
   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   streamlit run app.py
   ```
5. Open the local URL Streamlit prints (usually http://localhost:8501).

If PowerShell blocks activation, use:
```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

## Demo checklist
- `search_docs` -> ALLOWED
- `send_email` with normal text and no approval -> APPROVAL REQUIRED
- `send_email` with `My API key is sk_test_secret` -> BLOCKED
- `run_shell` -> BLOCKED
- Run multiple requests, then verify the hash chain and download JSON.

## Honest scope
This is a simulated proof-of-concept. It does not connect to an LLM or execute real tools. Secret detection is a simple demonstration rule, not robust DLP. The audit chain is tamper-evident within the current session, but is not immutable storage. Do not describe benchmark results unless you actually run the benchmarks.
