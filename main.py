# postMessage Finder: Burp Suite Extension to find postMessage functions and event listeners from a webpage. #postMessageFinder #freexpl0ited1
# By: Bastian Muhlhauser (xpl0ited1)
# Twitter: https://twitter.com/xpl0ited11
# Hackerone: https://hackerone.com/xpl0ited1

from burp import IBurpExtender
from burp import IScannerCheck, IContextMenuFactory
from burp import IScanIssue
from array import array
from javax.swing import JMenuItem
from java.util import ArrayList, List
import re

# Implement BurpExtender to inherit from multiple base classes
# IBurpExtender is the base class required for all extensions
# IScannerCheck lets us register our extension with Burp as a custom scanner check
class BurpExtender(IBurpExtender, IScannerCheck, IContextMenuFactory):

    # The only method of the IBurpExtender interface.
    # This method is invoked when the extension is loaded and registers
    # an instance of the IBurpExtenderCallbacks interface
    def	registerExtenderCallbacks(self, callbacks):
        # Put the callbacks parameter into a class variable so we have class-level scope
        self._callbacks = callbacks

        self._helpers = callbacks.getHelpers()
        self.context = None
        callbacks.registerContextMenuFactory(self)

        # Set the name of our extension, which will appear in the Extender tool when loaded
        self._callbacks.setExtensionName("xpl0ited1 postMessage Finder")

        # Register our extension as a custom scanner check, so Burp will use this extension
        # to perform active or passive scanning and report on scan issues returned
        self._callbacks.registerScannerCheck(self)
        return


    # This method is called when multiple issues are reported for the same URL
    # In this case we are checking if the issue detail is different, as the
    # issues from our scans include affected parameters/values in the detail,
    # which we will want to report as unique issue instances
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if (existingIssue.getIssueDetail() == newIssue.getIssueDetail()):
            return -1
        else:
            return 0

    # Implement the doPassiveScan method of IScannerCheck interface
    # Burp Scanner invokes this method for each base request/response that is passively scanned.
    def doPassiveScan(self, baseRequestResponse):
        # Local variables used to store a list of ScanIssue objects
        #print("Scanning passively")
        scan_issues = []
        tmp_issues = []

        # Create an instance of our CustomScans object, passing the
        # base request and response, and our callbacks object
        self._CustomScans = CustomScans(baseRequestResponse, self._callbacks)


        # Call the findRegEx method of our CustomScans object to check
        # the response for anything matching a specified regular expression
        # This one matches an IP
        regex_postmessage = "postMessage\("
        issuename_postmessage = "[postMessage Finder] postMessage function detected"
        issuelevel_postmessage = "Information"
        issuedetail_postmessage = """postMessage function Discovered: <b>$asset$</b>"""

        regex_addeventlistener = "addEventListener\(\"message\"|addEventListener\('message'|addEventListener\('MESSAGE'|addEventListener\(\"MESSAGE\"|\"message\"|\"MESSAGE\"|'message'|'MESSAGE'"
        issuename_addeventlistener = "[postMessage Finder] postMessage event listener detected"
        issuelevel_addeventlistener = "Information"
        issuedetail_addeventlistener = """postMessage event listener Discovered: <b>$asset$</b>"""

        regex_onmessage = "\.onMessage|\.onmessage|\"onmessage\"|\"onMessage\"|'onmessage'|'onMessage'"
        issuename_onmessage = "[postMessage Finder] postMessage onMessage event listener detected"
        issuelevel_onmessage = "Information"
        issuedetail_onmessage = """onMessage event listener Discovered: <b>$asset$</b>"""


        tmp_postmessage_issues = self._CustomScans.findRegEx(regex_postmessage, issuename_postmessage, issuelevel_postmessage, issuedetail_postmessage)
        tmp_addeventlistener_issues = self._CustomScans.findRegEx(regex_addeventlistener, issuename_addeventlistener,
                                                             issuelevel_addeventlistener, issuedetail_addeventlistener)
        tmp_onmessage_issues = self._CustomScans.findRegEx(regex_onmessage, issuename_onmessage,
                                                             issuelevel_onmessage, issuedetail_onmessage)

        # Add the issues from findRegEx to the list of issues to be returned
        scan_issues = scan_issues + tmp_postmessage_issues
        scan_issues = scan_issues + tmp_onmessage_issues
        scan_issues = scan_issues + tmp_addeventlistener_issues

        tmp_postmessage_issues = []
        tmp_onmessage_issues = []
        tmp_addeventlistener_issues = []


        # Finally, per the interface contract, doPassiveScan needs to return a
        # list of scan issues, if any, and None otherwise
        if len(scan_issues) > 0:
            return scan_issues
        else:
            return None

    # Invoke the "Search postMessage event handlers" Menu
    def createMenuItems(self, context):
        self.context = context
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Search postMessage event handlers", actionPerformed=self.menu_action))
        return menu_list

    # Menu Action: Obtain the http_request and http_response.
    # HTTP Response, if available, is analyzed to match some rules
    def menu_action(self, event):
        http_traffic = self.context.getSelectedMessages()
        for traffic in http_traffic:
            self.menuScan(traffic)
        return


    def menuScan(self, baseRequestResponse):
        # Local variables used to store a list of ScanIssue objects
        # print("Scanning passively")
        scan_issues = []
        tmp_issues = []

        # Create an instance of our CustomScans object, passing the
        # base request and response, and our callbacks object
        self._CustomScans = CustomScans(baseRequestResponse, self._callbacks)

        # Call the findRegEx method of our CustomScans object to check
        # the response for anything matching a specified regular expression
        regex_postmessage = "postMessage\("
        issuename_postmessage = "[postMessage Finder] postMessage function detected"
        issuelevel_postmessage = "Information"
        issuedetail_postmessage = """postMessage function Discovered: <b>$asset$</b>"""

        regex_addeventlistener = "addEventListener\(\"message\"|addEventListener\(\"MESSAGE\""
        issuename_addeventlistener = "[postMessage Finder] postMessage event listener detected"
        issuelevel_addeventlistener = "Information"
        issuedetail_addeventlistener = """postMessage event listener Discovered: <b>$asset$</b>"""

        regex_onmessage = "\.onMessage|\.onmessage|onmessage|onMessage"
        issuename_onmessage = "[postMessage Finder] postMessage onMessage event listener detected"
        issuelevel_onmessage = "Information"
        issuedetail_onmessage = """onMessage event listener Discovered: <b>$asset$</b>"""

        tmp_postmessage_issues = self._CustomScans.findRegEx(regex_postmessage, issuename_postmessage,
                                                             issuelevel_postmessage, issuedetail_postmessage)
        tmp_addeventlistener_issues = self._CustomScans.findRegEx(regex_addeventlistener, issuename_addeventlistener,
                                                                  issuelevel_addeventlistener,
                                                                  issuedetail_addeventlistener)
        tmp_onmessage_issues = self._CustomScans.findRegEx(regex_onmessage, issuename_onmessage,
                                                           issuelevel_onmessage, issuedetail_onmessage)

        # Add the issues from findRegEx to the list of issues to be returned
        scan_issues = scan_issues + tmp_postmessage_issues
        scan_issues = scan_issues + tmp_onmessage_issues
        scan_issues = scan_issues + tmp_addeventlistener_issues

        tmp_postmessage_issues = []
        tmp_onmessage_issues = []
        tmp_addeventlistener_issues = []

        # Finally, per the interface, report the issues
        if len(scan_issues) > 0:
            for issue in scan_issues:
                self._callbacks.addScanIssue(issue)


class CustomScans:
    def __init__(self, requestResponse, callbacks):
        # Set class variables with the arguments passed to the constructor
        self._requestResponse = requestResponse
        self._callbacks = callbacks

        # Get an instance of IHelpers, which has lots of useful methods, as a class
        # variable, so we have class-level scope to all the helper methods
        self._helpers = self._callbacks.getHelpers()

        # Put the parameters from the HTTP message in a class variable so we have class-level scope
        self._params = self._helpers.analyzeRequest(requestResponse.getRequest()).getParameters()
        return

    # This is a custom scan method to Look for all occurrences in the response
    # that match the passed regular expression
    def findRegEx(self, regex, issuename, issuelevel, issuedetail):
        scan_issues = []
        offset = array('i', [0, 0])
        response = self._requestResponse.getResponse()
        responseLength = 0
        if type(response) != type(None):
            responseLength = len(response)
        if responseLength == 0:
            return []

        myre = re.compile(regex, re.DOTALL)


        # Using the regular expression, find all occurrences in the base response
        match_vals = myre.findall(self._helpers.bytesToString(response))

        for ref in match_vals:
            url = self._helpers.analyzeRequest(self._requestResponse).getUrl()

            # For each matched value found, find its start position, so that we can create
            # the offset needed to apply appropriate markers in the resulting Scanner issue
            offsets = []
            start = self._helpers.indexOf(response,
                                          ref, True, 0, responseLength)
            offset[0] = start
            offset[1] = start + len(ref)
            offsets.append(offset)

            # Create a ScanIssue object and append it to our list of issues, marking
            # the matched value in the response.

            if (issuename == "[postMessage Finder] postMessage function detected"):
                try:
                    scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                                                 self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                                                 [self._callbacks.applyMarkers(self._requestResponse, None,
                                                                               offsets)],
                                                 issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                except:
                    continue
            elif (issuename == "[postMessage Finder] postMessage event listener detected"):
                try:
                    scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                                                 self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                                                 [self._callbacks.applyMarkers(self._requestResponse, None,
                                                                               offsets)],
                                                 issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                except:
                    continue
            elif (issuename == "[postMessage Finder] postMessage onMessage event listener detected"):
                try:
                    print("onMessage: " + ref)
                    scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                                                 self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                                                 [self._callbacks.applyMarkers(self._requestResponse, None,
                                                                               offsets)],
                                                 issuename, issuelevel, issuedetail.replace("$asset$", ref)))
                except:
                    continue
        return (scan_issues)

# Implementation of the IScanIssue interface with simple constructor and getter methods
class ScanIssue(IScanIssue):
    def __init__(self, httpservice, url, requestresponsearray, name, severity, detailmsg):
        self._url = url
        self._httpservice = httpservice
        self._requestresponsearray = requestresponsearray
        self._name = name
        self._severity = severity
        self._detailmsg = detailmsg

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return self._requestresponsearray

    def getHttpService(self):
        return self._httpservice

    def getRemediationDetail(self):
        return None

    def getIssueDetail(self):
        return self._detailmsg

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueType(self):
        return 0

    def getIssueName(self):
        return self._name

    def getSeverity(self):
        return "Information"

    def getConfidence(self):
        return "Firm"
