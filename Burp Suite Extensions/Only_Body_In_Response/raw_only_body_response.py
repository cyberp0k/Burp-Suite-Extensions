from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab
from javax.swing import JPanel, JScrollPane, JTextArea
from java.awt import BorderLayout
import json
from java.lang import String

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Wrapped Response Body")
        callbacks.registerMessageEditorTabFactory(self)

    def createNewInstance(self, controller, editable):
        return WrappedBodyTab(self._callbacks, editable)

class WrappedBodyTab(IMessageEditorTab):
    def __init__(self, callbacks, editable):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._editable = editable

        self._text_area = JTextArea()
        self._text_area.setLineWrap(True)
        self._text_area.setWrapStyleWord(True)
        self._text_area.setEditable(editable)

        self._scroll_pane = JScrollPane(self._text_area)

        self._panel = JPanel(BorderLayout())
        self._panel.add(self._scroll_pane, BorderLayout.CENTER)

        self._stored_body_bytes = None

    def getTabCaption(self):
        return "Wrapped Body"

    def getUiComponent(self):
        return self._panel

    def isEnabled(self, content, isRequest):
        return content is not None and not isRequest

    def setMessage(self, content, isRequest):
        self._stored_body_bytes = None
        if content is None:
            self._text_area.setText("")
            return

        try:
            analyzed = self._helpers.analyzeResponse(content)
            body_offset = analyzed.getBodyOffset()

            body_bytes = content[body_offset:]
            self._stored_body_bytes = body_bytes

            try:
                body_str = String(body_bytes, "UTF-8").toString()
            except:
                body_str = ""

            # Try prettify JSON
            try:
                parsed_json = json.loads(body_str)
                prettified = json.dumps(parsed_json, indent=4)
                self._text_area.setText(prettified)
            except:
                self._text_area.setText(body_str)

        except Exception as e:
            self._callbacks.printError("Error in setMessage: " + str(e))
            self._text_area.setText("")

    def getMessage(self):
        if self._editable:
            try:
                text = self._text_area.getText()
                # Return bytes using ISO-8859-1 encoding to preserve bytes in Burp
                return text.encode("ISO-8859-1")
            except:
                return self._stored_body_bytes
        else:
            return self._stored_body_bytes

    def isModified(self):
        # JTextArea does not track modification natively, so you might need your own flag if you want full support
        return False

    def getSelectedData(self):
        return self._text_area.getSelectedText()
