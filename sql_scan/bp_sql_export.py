# coding: utf-8
'''
@author: guimaizi
: burp插件
'''
import time
import subprocess
from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IBurpExtenderCallbacks
from burp import IContextMenuInvocation
from burp import IHttpRequestResponse
from javax.swing import JMenuItem
import os, json, subprocess


class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._actionName = "sql_scan"
        self._helers = callbacks.getHelpers()
        self._callbacks = callbacks
        callbacks.registerContextMenuFactory(self)
        return

    def createMenuItems(self, invocation):
        menu = []
        responses = invocation.getSelectedMessages()
        if len(responses) == 1:
            menu.append(JMenuItem(self._actionName, None, actionPerformed=lambda x, inv=invocation: self.Action(inv)))
            return menu
        return None

    def Action(self, invocation):
        request = invocation.getSelectedMessages().pop()
        analyzedRequest = self._helers.analyzeRequest(request)
        url = analyzedRequest.url
        headers = analyzedRequest.getHeaders()
        json_strs = {}
        for value in headers:
            strs = value.split(':', 1)
            # print strs
            if len(strs) > 1 and strs[0] not in ['Host', 'GET', 'POST'] and strs[0].startswith('GET') == False and strs[
                0].startswith('POST') == False:
                json_strs['%s' % strs[0]] = strs[1].lstrip()
        # method='GET'
        if analyzedRequest.getMethod() == "POST":
            body = request.getRequest().tostring()[analyzedRequest.getBodyOffset():]
            # method='POST'
        else:
            body = 'Null'
        path = os.getcwd().replace('\\','/')
        data = {"method": analyzedRequest.getMethod(), "url": str(url), "body": body, "headers": json_strs}
        json_data = json.dumps(data)
        with open('%s/export_json/burp_tmp.json' % path, 'w') as json_file:
            json_file.write(json_data)
        # subprocess.call('python3 /Users/guimaizi/hack-tool/burp_lib/test_vul.py')
        # os.system('open -a Terminal.app /Users/guimaizi/eclipse-workspace/testing_wave/start.sh')

        # os.system('start cmd /k python3  F:/DHK/Dhacker/BP2.11/burpsuite_pro_v2020.11/myplug/sql_scan/sql_scan_v1.0.py')

