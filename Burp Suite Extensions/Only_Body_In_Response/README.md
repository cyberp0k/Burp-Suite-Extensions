# 🧩 Burp Extension: Wrapped Response Body Viewer

A simple Burp Suite extension that adds a new tab to display only the **HTTP response body**, with optional **JSON prettification** and **line wrapping enabled** — making long responses much easier to read.

✅ Designed for:

- Readable HTML/text responses
- When headers are noise and you only care about the body

---




## 🛠 Installation

### Requirements

- [Burp Suite](https://portswigger.net/burp)
- [Jython 2.7.x standalone JAR](https://www.jython.org/download)

### Steps

1. Launch Burp.
2. Go to the **Extender** tab → **Options** → Set the path to the **Jython standalone JAR**.
3. In the **Extensions** tab, click **Add**:
   - **Extension type**: Python
   - **Select file**: Point to the `.py` file (e.g., `WrappedResponseBody.py`)
4. The extension should load and print:  
   `Extension loaded: Wrapped Response Body`

---


