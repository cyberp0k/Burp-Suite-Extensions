# 🗃️ Burp Suite Custom Extension Arsenal

This is my centralized directory for all custom Burp extensions, specifically tailored to accelerate manual hacking and Burp Suite workflows as a Bug Bounty Hunter and Penetration Tester. Stop wasting time on manually doing repetitive tasks which can be automated, and instantly identify the right tool to gain an edge.

---

## 📂 Directory of Extensions: The Toolkit Overview

This table lists the essential information for every custom extension in my collection.

| File Name | Language | Purpose / Description |
| :--- | :--- | :--- |
| **JSONContentTypeConverter.py** | Python (Jython) | Context menu tool to convert JSON requests into XML, Form-Data, or URL-Encoded formats, including automatic header and body restructuring. |
| **raw_only_body_response.py** | Python (Jython) | Shows just the response body. No headers, no clutter. Ideal when you're only interested in the actual content. |

---

## 📝 Changelog & Development Notes

Use this section to track key updates, bug fixes, and development notes for each extension.

### JSONContentTypeConverter.py

* **Initial Feature Set:** Added logic for dot-notation flattening and XML escape handling.

###  raw_only_body_response.py

* Adds a new tab labeled "Wrapped Body" to the message editor interface.
* Appears only for HTTP responses, not requests.
* Removes all response headers.

---

