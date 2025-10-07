from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenu, JMenuItem
from java.util import ArrayList
import json
import urllib
import random
import string
import traceback

class BurpExtender(IBurpExtender, IContextMenuFactory):
    EXTENSION_NAME = "JSON Content-Type Converter"
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Register extension
        callbacks.setExtensionName(self.EXTENSION_NAME)
        callbacks.registerContextMenuFactory(self)
        self.log("Extension loaded: Right-click a request with Accept: application/json or JSON body to convert.")
        
    def createMenuItems(self, invocation):
        context = invocation.getInvocationContext()
        menu_list = ArrayList()
        
        # Show menu for requests in Proxy, Repeater, or Intruder
        if context in [invocation.CONTEXT_MESSAGE_EDITOR_REQUEST, invocation.CONTEXT_MESSAGE_VIEWER_REQUEST]:
            selected_messages = invocation.getSelectedMessages()
            if selected_messages and len(selected_messages) == 1:
                request = selected_messages[0].getRequest()
                request_info = self._helpers.analyzeRequest(request)
                headers = request_info.getHeaders()
                method = request_info.getMethod()
                
                # Check for Accept: application/json or POST/PUT with Content-Type: application/json
                has_json_accept = False
                has_json_content = False
                for header in headers:
                    if header.lower().startswith('accept:') and 'application/json' in header.lower():
                        has_json_accept = True
                    if header.lower().startswith('content-type:') and 'application/json' in header.lower():
                        has_json_content = True
                
                # Validate JSON body for POST/PUT
                if method in ["POST", "PUT"] and has_json_content:
                    body_bytes = request[request_info.getBodyOffset():]
                    body_str = self._helpers.bytesToString(body_bytes).strip()
                    try:
                        json.loads(body_str)
                    except ValueError:
                        has_json_content = False
                        self.log("Invalid JSON body; menu not shown for this request")
                
                if has_json_accept or has_json_content:
                    # Create submenu
                    main_menu = JMenu("JSON Content-Type Converter")
                    menu_list.add(main_menu)
                    
                    # Add conversion options
                    main_menu.add(JMenuItem("Convert to XML", actionPerformed=lambda x: self.convert_request(selected_messages[0], "application/xml")))
                    main_menu.add(JMenuItem("Convert to Form-Data", actionPerformed=lambda x: self.convert_request(selected_messages[0], "multipart/form-data")))
                    main_menu.add(JMenuItem("Convert to URL-Encoded", actionPerformed=lambda x: self.convert_request(selected_messages[0], "application/x-www-form-urlencoded")))
        
        return menu_list if menu_list else None
        
    def convert_request(self, message_info, target_mime):
        try:
            request = message_info.getRequest()
            request_info = self._helpers.analyzeRequest(request)
            headers = request_info.getHeaders()
            method = request_info.getMethod()
            
            # Log original request
            self.log("Original headers: " + str(headers))
            body_bytes = request[request_info.getBodyOffset():]
            body_str = self._helpers.bytesToString(body_bytes).strip()
            self.log("Original body: " + body_str)
            
            # Update headers
            new_headers = []
            accept_updated = False
            content_type_updated = False
            boundary = None
            for header in headers:
                if header.lower().startswith("accept:") and "application/json" in header.lower():
                    new_headers.append("Accept: {0}".format(target_mime))
                    accept_updated = True
                elif header.lower().startswith("content-type:") and "application/json" in header.lower():
                    if target_mime == "multipart/form-data":
                        boundary = "----WebKitFormBoundary" + ''.join(random.choice(string.ascii_uppercase) for _ in range(16))
                        new_headers.append("Content-Type: {0}; boundary={1}".format(target_mime, boundary))
                    else:
                        new_headers.append("Content-Type: {0}; charset=UTF-8".format(target_mime))
                    content_type_updated = True
                else:
                    new_headers.append(header)
            
            # Add Accept header if missing
            if not accept_updated and not any(h.lower().startswith("accept:") for h in headers):
                new_headers.append("Accept: {0}".format(target_mime))
            
            # Convert body for POST/PUT with JSON
            new_body_bytes = body_bytes
            if method in ["POST", "PUT"] and content_type_updated:
                try:
                    json_data = json.loads(body_str)
                    self.log("Parsed JSON: " + str(json_data))
                    
                    if target_mime == "application/xml":
                        new_body = self.json_to_xml(json_data)
                    elif target_mime == "multipart/form-data":
                        new_body = self.json_to_form_data(json_data, boundary)
                    elif target_mime == "application/x-www-form-urlencoded":
                        new_body = self.json_to_url_encoded(json_data)
                    
                    self.log("Converted body ({0}): {1}".format(target_mime, new_body))
                    # Encode to UTF-8 and remove BOM
                    new_body_bytes = self._helpers.stringToBytes(new_body.encode('utf-8').decode('utf-8').encode('utf-8'))
                except ValueError as e:
                    self.log("Error: Invalid JSON body; skipping body conversion: " + str(e))
            
            # Update request
            new_request = self._helpers.buildHttpMessage(new_headers, new_body_bytes)
            message_info.setRequest(new_request)
            self.log("Request converted: Accept to {0}{1}".format(
                target_mime,
                ", Content-Type to {0} with converted body".format(target_mime) if content_type_updated else ""
            ))
            
        except Exception as e:
            self.log("Error converting request: " + str(e))
            traceback.print_exc()
    
    def json_to_xml(self, json_data):
        """Convert JSON to XML string without root wrapper."""
        def escape_xml(text):
            """Escape XML special characters."""
            if text is None:
                return ""
            text = str(text)
            return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&apos;')
        
        def dict_to_xml(d, indent=0):
            xml_lines = []
            indent_str = "  " * indent
            for key, value in d.items():
                key = escape_xml(key)
                if isinstance(value, dict):
                    xml_lines.append("{0}<{1}>".format(indent_str, key))
                    xml_lines.extend(dict_to_xml(value, indent + 1))
                    xml_lines.append("{0}</{1}>".format(indent_str, key))
                else:
                    xml_lines.append("{0}<{1}>{2}</{1}>".format(indent_str, key, escape_xml(value)))
            return xml_lines
        
        xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>']
        if isinstance(json_data, dict):
            xml_lines.extend(dict_to_xml(json_data))
        else:
            xml_lines.append("<data>{0}</data>".format(escape_xml(json_data)))
        
        return "\n".join(xml_lines)
    
    def json_to_form_data(self, json_data, boundary):
        """Convert JSON to multipart/form-data."""
        parts = []
        
        def flatten_dict(d, parent_key=""):
            for key, value in d.items():
                new_key = "{0}.{1}".format(parent_key, key) if parent_key else key
                if isinstance(value, dict):
                    flatten_dict(value, new_key)
                else:
                    parts.append((new_key, str(value)))
        
        if isinstance(json_data, dict):
            flatten_dict(json_data)
        else:
            parts.append(("data", str(json_data)))
        
        body = ""
        for name, value in parts:
            body += "--{0}\r\n".format(boundary)
            body += 'Content-Disposition: form-data; name="{0}"\r\n\r\n'.format(name)
            body += "{0}\r\n".format(value)
        body += "--{0}--\r\n".format(boundary)
        return body
    
    def json_to_url_encoded(self, json_data):
        """Convert JSON to application/x-www-form-urlencoded."""
        params = []
        
        def flatten_dict(d, parent_key=""):
            for key, value in d.items():
                new_key = "{0}.{1}".format(parent_key, key) if parent_key else key
                if isinstance(value, dict):
                    flatten_dict(value, new_key)
                else:
                    params.append((new_key, str(value)))
        
        if isinstance(json_data, dict):
            flatten_dict(json_data)
        else:
            params.append(("data", str(json_data)))
        
        return urllib.urlencode(params)
    
    def log(self, message):
        print message