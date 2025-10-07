# 🚀 JSON Content-Type Converter for Burp Suite

A simple yet powerful Burp Suite extension written in Python to seamlessly convert requests that either **Accept: `application/json`** or contain a **JSON body** into different content types: **XML**, **Form-Data**, or **URL-Encoded**.

---

## ✨ Features at a Glance

| Feature | Description |
| :--- | :--- |
| **🔄 Seamless Conversion** | Convert JSON requests to XML, Form-Data, or URL-Encoded formats. |
| **🛠️ Automatic Header Update** | Automatically modifies `Accept` and `Content-Type` headers to match the target format. |
| **🔗 Dot Notation Flattening** | Flattens nested JSON objects (e.g., `{"user": {"id": 1}}`) into dot-notation parameters (`user.id=1`) for Form-Data and URL-Encoded. |
| **🖱️ Context Menu Access** | Easily accessible via right-click in Proxy, Repeater, and Intruder. |

---

## 🛠️ Prerequisites & Setup

To run this Python extension, you must have **Jython** configured in Burp Suite.

### 1. Download Jython

* Download the `jython-standalone.jar` file (version **2.7.x** is recommended).

### 2. Configure Burp Suite

1.  Open Burp Suite.
2.  Go to **Extender** $\rightarrow$ **Options**.
3.  In the **Python Environment** section, set the **Location of the Jython standalone JAR file** to the path where you saved `jython-standalone.jar`.

---

## 📥 Installation

1.  Save the provided Python code as `JSONContentTypeConverter.py`.
2.  In Burp Suite, navigate to **Extender** $\rightarrow$ **Extensions**.
3.  Click the **Add** button.
4.  In the dialog:
    * Set **Extension type** to **Python**.
    * Select the **Extension file** (`JSONContentTypeConverter.py`).
5.  Click **Next**. A successful load will display a confirmation message in the **Output** tab.

---

## 🎯 Usage

The conversion options appear in the context menu for requests that meet one of these criteria:
* The request headers include **`Accept: application/json`**.
* The method is **POST** or **PUT** and the request contains a valid **JSON body** with **`Content-Type: application/json`**.

### Conversion Steps:

1.  In **Proxy History**, **Repeater**, or **Intruder**, view a qualifying request.
2.  **Right-click** on the request panel.
3.  Hover over the **JSON Content-Type Converter** submenu.
4.  Select your desired conversion:

    * **Convert to XML**
    * **Convert to Form-Data**
    * **Convert to URL-Encoded**

> 💡 **Tip:** The extension modifies the request *in place*. Check the **Extender Output** tab for detailed logging of the conversion process.

---

## ⚙️ Conversion Logic

The core power of the extension lies in how it transforms both headers and the request body simultaneously.

| Original Content-Type | Target Format | Header Changes | Body Conversion Method |
| :--- | :--- | :--- | :--- |
| `application/json` | **`application/xml`** | Sets `Accept` and `Content-Type` to the target. | JSON objects become nested XML elements. |
| `application/json` | **`multipart/form-data`** | Sets `Accept` and `Content-Type` to the target, including a unique boundary. | Flattened JSON keys (using dot notation) are structured into multipart parts. |
| `application/json` | **`application/x-www-form-urlencoded`** | Sets `Accept` and `Content-Type` to the target. | Flattened JSON keys (using dot notation) are concatenated and URL-encoded (`key=value&key2=value2`). |

---

### Example Conversion:

| Original JSON Body | Target Format | Converted Body |
| :--- | :--- | :--- |
| `{"user": {"id": 42, "name": "Alice"}}` | **URL-Encoded** | `user.id=42&user.name=Alice` |
| `{"user": {"id": 42, "name": "Alice"}}` | **XML** | `<?xml...?>`<br>`<user>`<br>&nbsp;&nbsp;`<id>42</id>`<br>&nbsp;&nbsp;`<name>Alice</name>`<br>`</user>` |
