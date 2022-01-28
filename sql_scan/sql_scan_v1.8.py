# coding: utf-8

import time
import ast
import os, threading
from watchdog.observers import Observer
from watchdog.events import *
from watchdog.utils.dirsnapshot import DirectorySnapshot, DirectorySnapshotDiff
import requests
import json, copy
from urllib import parse
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.preprocessing import StandardScaler
from scipy import spatial
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
ggg = None
kill = None
proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}

class process_http_request:
    def __init__(self):
        self.list_data = []
        self.flag_list = []
        self.path = os.getcwd().replace('\\', '/') + '/export_json'
        with open('%s/burp_tmp.json' % self.path, 'r') as f:
            self.test_jsonssss = f
        with open('%s/burp_tmp.json' % self.path, 'r') as f:
            self.test_json = json.load(f)
        payload_path = os.getcwd().replace('\\', '/')
        with open('%s/payload.txt' % payload_path, "r") as f:
            s = f.readlines()
            self.payload_list = [i.strip() for i in s]
    def get_json(self):
        # path = os.getcwd().replace('\\', '/') + '/export_json'
        with open('%s/burp_tmp.json' % self.path, 'r') as f:
            self.test_json = json.load(f)
        return self.test_json
    def type_param(self, param_data):
        '''
        返回数据类型  INT Json List Url String
        :param param_data:
        :return:
        '''
        try:
            int(param_data)
            return 'Int'
        except:
            pass
        try:
            if type(param_data) == type({'a': 1}): return 'Json'
        except:
            pass
        try:
            if type(json.loads(param_data)) == type({'a': 1}): return 'Json'
        except:
            pass
        try:
            if type(param_data) == type([]): return 'List'
        except:
            pass
        if parse.unquote(param_data).startswith('http://') or parse.unquote(param_data).startswith(
                'https://'): return 'Url'
        return 'String'

    def process_payload(self, json_data, num, payload):
        '''
        Payload处理 0追加 1 数组 a=1==>a[]=1 2.xff usagent
        :param json_data:
        :param num:
        :param payload:
        :return:
        '''

        if num == 0:
            json_data = str(json_data) + payload
        elif num == 1 and bool('json' in self.test_json['headers']['Content-Type']) == False:  # 改为数组
            json_data = str(json_data) + payload

        else:
            pass
        return json_data

    def process_json(self, http_request_body, param_name=''):
        '''
        遍历json键名
        :param http_request_body:
        :param param_name:
        :return:
        '''
        for name in http_request_body:

            # print(name)
            if param_name != '':
                self.list_data.append(
                    (param_name + '.' + name, self.type_param(http_request_body[name]), http_request_body[name]))
            else:
                self.list_data.append((name, self.type_param(http_request_body[name]), http_request_body[name]))
            if isinstance(http_request_body[name], dict):
                if param_name != '':
                    self.process_json(http_request_body[name], param_name + '.' + name)
                else:
                    self.process_json(http_request_body[name], name)

    def callback_set_json(self, http_request, data):
        http_request["param_name"] = data["param_name"]
        http_request["param_value"] = data["param_value"]
        http_request["param_type"] = data["param_type"]
        return http_request

    def callback_json_http_request(self, http_request_body, param_name_list, payload, payload_num):
        '''
        Json格式http body返回
        :param http_request_body:
        :param param_name_list:json键名
        :param payload:
        :param num:
        :return:
        '''
        param_name_list = param_name_list.split('.')
        num_param = len(param_name_list)
        num = 0
        task_name = 'http_request_body[param_name_list[%s]]' % num
        for i in range(num_param):
            if num == num_param - 1:
                param_type = self.type_param(eval(task_name))
                param_value = eval(task_name)
                item = eval('task_name') + " = self.process_payload(" + eval('task_name') + ", payload_num, payload)"
                exec(item)
            num = num + 1
            task_name = task_name + '[param_name_list[%s]]' % num
        return {"param_name": '.'.join(param_name_list), "param_value": param_value, "param_type": param_type,
                "data": http_request_body}

    def callback_param_http_request(self, http_request_body, param, payload, payload_num):

        '''
        a=str&b=str&c=1 返回
        :param http_request_body:
        :param param: 参数名
        :param payload:
        :param num:
        :return:
        '''
        try:
            list_data = []
            # task_list = list(set(http_request_body.split('&')))
            task_list = http_request_body.split('&')
            if '' in task_list:
                task_list.remove('')
            # print(task_list)
            for tmp in task_list:
                # print(tmp.split('=')[0])
                # print(param)
                tmp = copy.deepcopy(tmp)

                if '=' in tmp and str(tmp.split('=')[0]) == param:
                    if payload_num == 1:  # list_data才是返回的拼接参数
                        param_name = tmp.split('=')[0] + '[]'
                        param_value = tmp.split('=')[1]
                        param_type = self.type_param(tmp.split('=')[1])
                        list_data.append(
                            tmp.split('=')[0] + '[]' + '=' + self.process_payload(tmp.split('=')[1], payload_num,
                                                                                  payload))  # 控制参数的拼接
                    else:
                        param_name = tmp.split('=')[0]
                        param_value = tmp.split('=')[1]
                        param_type = self.type_param(tmp.split('=')[1])
                        list_data.append(
                            tmp.split('=')[0] + '=' + self.process_payload(tmp.split('=')[1], payload_num, payload))

                else:

                    if len(tmp.split('=')) == 2:
                        list_data.append(tmp.split('=')[0] + '=' + tmp.split('=')[1])
                    else:
                        param_value = 'Null'
                        param_type = 'Null'
                        list_data.append(tmp.split('=')[0] + '=' + param_value)

            return {"param_name": param_name, "param_value": param_value, "param_type": param_type,
                    "param_data": '&'.join(list_data)}
        except:
            return {}

    def process_param(self, http_request_body, param_name=''):
        '''
        遍历参数名 a=str&b=str&c=1  这类参数处理
        :param http_request:
        :param param_name:
        :return:
        '''
        try:
            callback_param = []
            for tmp in http_request_body.split('&'):
                if len(tmp.split('=')) == 2:
                    callback_param.append((tmp.split('=')[0], self.type_param(tmp.split('=')[1]), tmp.split('=')[1]))
                else:
                    callback_param.append((tmp.split('=')[0], 'Null', 'Null'))
            return callback_param
        except Exception as e:
            print(e)
            return []

    def callback_param_list(self, http_request):
        '''

        :param http_request:
        :return: (参数名 , 参数值类型)
        [('method', 'String'), ('name', 'String'), ('age', 'Int'), ('data', 'Json'), ('data.name', 'String'), ('sada', 'Int')]
        '''
        param_list = []
        query = parse.urlparse(http_request['url']).query
        if http_request['method'] == 'GET' and query != '':
            param_list.extend(self.process_param(query))
        elif http_request['method'] == 'POST' and http_request['body'] != '':
            if query != '': param_list.extend(self.process_param(query))
            if self.type_param(http_request['body']) == 'Json':
                if type(http_request['body']) == type({}):
                    self.process_json(http_request['body'])
                else:
                    self.process_json(json.loads(http_request['body']))
                param_list.extend(self.list_data)
            else:
                param_list.extend(self.process_param(http_request['body']))
        self.list_data = []

        return param_list

    def callback_http_request(self, http_request, param, payload, payload_num,waf_flag):
        # (self.test_json, item[0], payload, i)
        '''
        返回设置payload后的http请求包
        :param http_request:
        :param param:
        :param payload:
        :param payload_num:
        :return:
        '''

        http_request = copy.deepcopy(http_request)

        if self.type_param(http_request['body']) == 'Json':

            http_request['body'] = json.loads(http_request['body'])

        url_process = parse.urlparse(http_request['url'])
        http_get_data = self.callback_param_http_request(copy.deepcopy(url_process.query), param, payload, payload_num)

        if http_request['method'] == 'GET' and url_process.query != '' and http_get_data != {}:

            http_request['url'] = url_process.scheme + '://' + url_process.netloc + url_process.path + '?' + \
                                  http_get_data['param_data']
            http_request = self.callback_set_json(http_request, http_get_data)
            return http_request
        elif http_request['method'] == 'POST' and http_request['body'] != 'Null':

            if url_process.query != '' and http_get_data != {}:
                http_request['url'] = url_process.scheme + '://' + url_process.netloc + url_process.path + '?' + \
                                      http_get_data['param_data']
                http_request = self.callback_set_json(http_request, http_get_data)

                return http_request
            if self.type_param(http_request['body']) == 'Json':
                json_data = self.callback_json_http_request(http_request['body'], param, payload, payload_num)
                http_request = self.callback_set_json(http_request, json_data)
                http_request["body"] = json_data["data"]
                return http_request
            elif http_request['body'] != 'Null':
                post_data = self.callback_param_http_request(copy.deepcopy(http_request["body"]), param, payload,
                                                             payload_num)
                if post_data != {}:
                    http_request = self.callback_set_json(http_request, post_data)
                    http_request["body"] = post_data["param_data"]
                    return http_request
        return http_request

    def Text_comparison(self, list_html):

        list_num = []
        list_signal = []
        # 步骤一
        try:
            cv = CountVectorizer()
            data = cv.fit_transform(list_html)
            std = StandardScaler()
            data_list = std.fit_transform(data.toarray())
            # print(data_list)
            # 步骤二
            for line in data_list:
                if len(set(line)) ==1:
                    continue
                list_num.append(round(spatial.distance.cosine(data_list[0], line), 2))
            num = 0
            # print(list_num)
            # 步骤三
            for signal in list_num:
                if signal != 0:
                    if 1 / signal * 100 < 75:
                        list_signal.append(num)
                num = num + 1
            # print(list_signal)
        except:
            print("内容对比计算错误--280行-290行--code--所有响应为空/0")
        return list_signal


    def sleep_time(self, con_time):  # 时间盲注匹配容易产生误报，可以自己调节延迟和payload的请求
        if 2.6 <= con_time <= 3.4 or 5.6 <= con_time <= 6.4:
            return True
        else:
            return False


    def payload_scan(self,waf_flag):
        htm_list = []
        datalist = []
        flag_list = []
        data_body = []


        for i in range(0, 3):  # 0 == 追加 1===检测是否为json类型，不是则变为数组[]参数检测，2==只是xff，us头检测，不需要构造参数返回值
            for payload in self.payload_list:
                if i == 2:
                    self.test_json = self.get_json()
                    self.test_json['headers']['X-Forwarded-For'] = payload
                    self.test_json['headers']['User-Agent'] = payload
                    data = self.test_json
                    self.scan_request(data,htm_list,datalist,flag_list,data_body,1)  # 1 ==因为直接读的原json，没有load_json,所有需要用data请求

                else:
                    for item in self.callback_param_list(self.test_json):
                        data = self.callback_http_request(self.test_json, item[0], payload, i, waf_flag)
                        self.scan_request(data,htm_list,datalist,flag_list,data_body,0)
                    #   if item[1] != 'Json':

        # 基于内容相似度匹配 - -鬼麦子
        t = self.Text_comparison(htm_list)

        flag_list.append(bool(t))  # 文本相似度的True&False

        if bool(t):
            for vul_flag in t:

                if 'GET' in data['method']:
                    print('exist SQL Vulnerability___(Text comparison)  ' + datalist[vul_flag])
                    self.output_data('exist SQL Vulnerability___(Text comparison)  ' + datalist[vul_flag])
                    continue
                else:
                    print(
                        'exist SQL Vulnerability___(Text comparison)  ' + str(datalist[vul_flag]) + '           ' + str(
                            data_body[vul_flag]))
                    self.output_data(
                        'exist SQL Vulnerability___(Text comparison)  ' + str(
                            datalist[vul_flag]) + '           ' + '\n' + str(data['headers']) + '\n' + str(
                            data_body[vul_flag]))
                    self.output_html(htm_list[vul_flag] + '\n\n\n')

                    continue

        if True not in flag_list and kill != 0:  # 当所有常规扫描后的结果没有检测到异常True，将自动开启bypass请求
            self.bypass_waf()  # 死循环, 设置全局标志kill，执行过scan(1)后kill变0
            print("---------已完成调用bypasswaf请求扫描----------")

        return

    def scan_request(self,data,htm_list,datalist,flag_list,data_body,req_type):

        reg = "执行SQL|database|mysql|syntax error"  # 匹配报错sql关键字
        datalist.append(data['url'])
        data_body.append(data['body'])
        # print(data['url'])
        # 基于文本正则关键字匹配

        if 'GET' in data['method']:
            try:
                req = requests.get(url=data['url'], headers=data['headers'], verify=False, timeout=3)

                con_get = req.text
                con_time = req.elapsed.total_seconds()
            except:
                    return


                # self.sleep_time()
            # print(data['headers'])
            # print(con_get)
            htm_list.append(con_get)
            flag = bool(re.findall(reg, con_get))
            print(len(htm_list))
            flag_list.append(flag)
            if flag:
                print('exist SQL Vulnerability___(Regular matching)   ' + data['url'])
                self.output_data('exist SQL Vulnerability___(Regular matching)   ' + data['url'])
                # continue
            flag_time = self.sleep_time(con_time)  # 延迟注入检测

            if flag_time:
                print('exist SQL Vulnerability___(Delay/Time Response)   ' + data['url'])
                self.output_data('exist SQL Vulnerability___(Delay/Time Response)   ' + data['url'])
                # continue


        elif 'POST' in data['method']:
            if 'json' in self.test_json['headers']['Content-Type']:

                try:
                    if req_type ==1:
                        req = requests.post(url=data['url'], headers=data['headers'],
                                            data=data['body'],
                                            verify=False, timeout=3, proxies=proxies)
                    else:
                        req = requests.post(url=data['url'], headers=data['headers'],
                                            json=data['body'],
                                            verify=False, timeout=3, proxies=proxies)

                    con_post = req.text
                    con_time = req.elapsed.total_seconds()
                    htm_list.append(con_post)

                    flag = bool(re.findall(reg, con_post))

                    flag_list.append(flag)
                    if flag:
                        print(
                            'exist SQL Vulnerability___(Regular matching)   ' + data[
                                'url'] + '           ' +
                            data[
                                'body'])
                        self.output_data(
                            'exist SQL Vulnerability___(Regular matching)   ' + data[
                                'url'] + '\n\n' + str(data['headers']) + '\n' + data['body'])
                        # continue
                    flag_time = self.sleep_time(con_time)

                    if flag_time:
                        print(
                            'exist SQL Vulnerability___(Delay/Time Response)   ' + str(
                                data['url']) + '           ' + str(data['body']))

                        self.output_data(
                            'exist SQL Vulnerability___(Delay/Time Response)   ' + str(
                                data['url']) + str(data['body']))
                        # continue
                except:
                    return


            else:
                try:
                    req = requests.post(url=data['url'], headers=data['headers'],
                                        data=data['body'],
                                        verify=False, timeout=3, proxies=proxies)
                    con_post = req.text
                    con_time = req.elapsed.total_seconds()
                    htm_list.append(con_post)

                    flag = bool(re.findall(reg, con_post))
                    flag_list.append(flag)
                    if flag:
                        print(
                            'exist SQL Vulnerability___(Regular matching)   ' + data[
                                'url'] + '           ' +
                            data[
                                'body'])
                        self.output_data(
                            'exist SQL Vulnerability___(Regular matching)   ' + data[
                                'url'] + '\n\n' + str(data['headers']) + '\n' + data['body'])
                        # continue
                    flag_time = self.sleep_time(con_time)

                    if flag_time:
                        print(
                            'exist SQL Vulnerability___(Delay/Time Response)   ' + str(
                                data['url']) + '           ' + str(data['body']))

                        self.output_data(
                            'exist SQL Vulnerability___(Delay/Time Response)   ' + str(
                                data['url']) + str(data['body']))
                        # continue
                except:
                    return

        else:  # put 修改？
            con_put = requests.put(url=data['url'], headers=data['headers'], data=data['body'],
                                   verify=False).text
            htm_list.append(con_put)
            flag = bool(re.findall(reg, con_put))
            flag_list.append(flag)
            if flag:
                print('exist SQL Vulnerability___(Regular matching)  ' + data['url'])
                self.output_data('exist SQL Vulnerability___(Regular matching)  ' + data['url'])

        print(len(htm_list))




    def scan(self, waf_flag=0):  # waf_flag 0 关闭 ，1 开启bypass请求

        if waf_flag == 1:
            global kill
            kill = 0
            self.test_json = self.get_json()
            print("---------bypasswaf扫描----------")
            for ms in range(1,3):
                if ms == 1:

                    self.test_json['headers']['Content-Encoding'] = 'gzip'
                    self.payload_scan(waf_flag)
                    self.test_json = self.get_json()
                    continue
                elif ms == 2 and bool('json' in self.test_json['headers']['Content-Type']) == False:
                    self.test_json['headers']['Content-Type'] = 'multipart/form-data'
                    self.payload_scan(waf_flag)
                    self.test_json = self.get_json()
                    continue
        print("---------常规扫描----------")
        self.payload_scan(waf_flag)
        kill = 1
        return

    def bypass_waf(self):
        self.scan(1)

    def output_data(self, i):
        with open('vul_sql.txt', "a", encoding='utf-8') as f:
            f.write(i + "\n")
    def output_html(self, i):
        with open('vul_html.html', "a", encoding='utf-8') as f:
            f.write(i + "\n")

    def listen(self):
        # path = os.getcwd().replace('\\', '/') + '/export_json'
        monitor = DirMonitor(self.path)
        monitor.start()
        print("-------------------------Listening-------------------------")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            monitor.stop()

class FileEventHandler(FileSystemEventHandler):
    def __init__(self, aim_path):
        FileSystemEventHandler.__init__(self)
        self.aim_path = aim_path
        self.timer = None
        self.snapshot = DirectorySnapshot(self.aim_path)

    def on_any_event(self, event):
        if self.timer:
            self.timer.cancel()

        self.timer = threading.Timer(0.2, self.checkSnapshot)
        self.timer.start()

    def checkSnapshot(self):
        snapshot = DirectorySnapshot(self.aim_path)
        diff = DirectorySnapshotDiff(self.snapshot, snapshot)
        self.snapshot = snapshot
        self.timer = None
        print('请求包变化，开始执行scan')
        test = process_http_request()
        print("=================")
        test.scan()



class DirMonitor(object):
    """文件夹监视类"""

    def __init__(self, aim_path):
        """构造函数"""
        self.aim_path = aim_path
        self.observer = Observer()

    def start(self):
        """启动"""
        event_handler = FileEventHandler(self.aim_path)
        self.observer.schedule(event_handler, self.aim_path, True)
        self.observer.start()

    def stop(self):
        """停止"""
        self.observer.stop()



banner = '''
           _                         
 ___  __ _| |    ___  ___ __ _ _ __  
/ __|/ _` | |   / __|/ __/ _` | '_ \ 
\__ \ (_| | |   \__ \ (_| (_| | | | |
|___/\__, |_|___|___/\___\__,_|_| |_|
        |_||_____|    ------v.1.8-------- author:default                  
'''
if __name__ == '__main__':
    print(banner)
    # 监听模式
    scan = process_http_request()
    scan.listen()
    # 单次扫描模式
    # scan = process_http_request()
    # scan.scan()
    # scan.Scanjson()
