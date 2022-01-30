# coding: utf-8
"""
@Time :    6/18/2021 17:02
@Author:  guimaizi
@File: process_http_request.py
@Software: PyCharm
"""

import time
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

kill = None
proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}

class process_http_request:
    def __init__(self):
        self.list_data = []
        path = os.getcwd().replace('\\', '/') + '/export_json'
        with open('%s/burp_tmp.json' % path, 'r') as f:
            self.test_json = json.load(f)
        payload_path = os.getcwd().replace('\\', '/')
        with open('%s/payload.txt' % payload_path, "r") as f:
            s = f.readlines()
            self.payload_list = [i.strip() for i in s]

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
        Payload处理 0追加 1替换 2数组 a=1==>a[]=1 3.bypasswaf
        :param json_data:
        :param num:
        :param payload:
        :return:
        '''
        # print(num)
        if num == 0:
            json_data = str(json_data) + payload
        elif num == 1:
            json_data = payload
        elif num == 2:  # 改为数组
            json_data = str(json_data) + payload
        # elif num == 3:  # 添加bypass模式1

        # elif num == 2:
        #     json_data = payload + str(json_data)
        # elif num == 3:
        #     json_data = payload + str(json_data)
        #     print(json_data)
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
                    if payload_num == 2:  # list_data才是返回的拼接参数
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
            # print(list_data)
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

    def callback_http_request(self, http_request, param, payload, payload_num):
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
                list_num.append(round(spatial.distance.cosine(data_list[0], line), 2))
            num = 0
            print(list_num)
            # 步骤三
            for signal in list_num:
                if signal != 0:
                    if 1 / signal * 100 < 80:
                        list_signal.append(num)
                num = num + 1
            print(list_signal)
        except:
            print("内容对比计算错误--280行-290行--code--所有响应为空/0")
        return list_signal

    def header_scan(self, payload):
        # 添加header的扫描模块
        # 1.xff扫描

        path = os.getcwd().replace('\\', '/') + '/export_json'
        with open('%s/burp_tmp.json' % path, 'r') as f:
            data = self.test_json
            data['headers']['X-Forwarded-For'] = payload
        return data

    def sleep_time(self, con_time):
        if 1.6 <= con_time <= 2.4 or 3.6 <= con_time <= 4.4:
            return True
        else:
            return False

    def test(self):
        print(self.payload_list)

    def scan(self, waf_flag=0):  # waf_flag 0 关闭 ，1 开启bypass请求


        reg = "error|database|mysql"  # 匹配报错sql关键字
        # path = os.getcwd().replace('\\', '/') + '/export_json'
        # with open('%s/burp_tmp.json' % path, 'r') as f:
        #
        #     test_json = json.load(f)

        htm_list = []
        datalist = []
        flag_list = []

        for item in self.callback_param_list(self.test_json):

            if item[1] != 'Json':

                for i in range(0, 3):  # 追加/替换/数组/污染/bypasswaf/场景合并  (污染和其他场景未添加)
                    for payload in self.payload_list:
                        data = self.callback_http_request(self.test_json, item[0], payload, i)
                        if waf_flag == 1:

                            global kill
                            kill = 0
                            for ms in range(1, 4):

                                if ms == 1:
                                    data['headers']['Content-Encoding'] = 'gzip'
                                    continue
                                elif ms == 2:
                                    data['headers']['Content-Type'] = 'multipart/form-data'

                                elif ms == 3:  # xff扫描
                                    data = self.header_scan(payload)
                                else:
                                    break
                        datalist.append(data['url'])

                        # print(data['url'])
                        # 基于文本正则关键字匹配

                        if 'GET' in data['method']:
                            con_get = requests.get(url=data['url'], headers=data['headers'], verify=False,
                                                   proxies=proxies).text
                            con_time = requests.get(url=data['url'], headers=data['headers'], verify=False,
                                                   proxies=proxies).elapsed.total_seconds()

                            # self.sleep_time()
                            # print(data['headers'])
                            # print(con_get)
                            htm_list.append(con_get)
                            flag = bool(re.findall(reg, con_get))

                            flag_list.append(flag)
                            if flag:
                                print('exist SQL Vulnerability___(Regular matching)   ' + data['url'])
                                self.output_data('exist SQL Vulnerability___(Regular matching)   ' + data['url'])
                                continue
                            flag_time = self.sleep_time(con_time)  # 三斤要求的延迟注入检测
                            if flag_time:
                                print('exist SQL Vulnerability___(Delay/Time Response)   ' + data['url'])
                                self.output_data('exist SQL Vulnerability___(Delay/Time Response)   ' + data['url'])
                                continue


                        elif 'POST' in data['method']:

                            con_post = requests.post(url=data['url'], headers=data['headers'], data=data['body'],
                                                     verify=False, proxies=proxies).text
                            con_time = requests.post(url=data['url'], headers=data['headers'], data=data['body'], verify=False,
                                                   proxies=proxies).elapsed.total_seconds()

                            htm_list.append(con_post)
                            flag = bool(re.findall(reg, con_post))
                            flag_list.append(flag)
                            if flag:
                                print('exist SQL Vulnerability___(Regular matching)   ' + data['url']+'           '+data['body'])
                                self.output_data('exist SQL Vulnerability___(Regular matching)   ' + data['url']+'           '+data['body'])

                                continue
                            flag_time = self.sleep_time(con_time)

                            if flag_time:
                                print('exist SQL Vulnerability___(Delay/Time Response)   ' + data['url']+'           '+data['body'])
                                print(data['headers'])
                                self.output_data('exist SQL Vulnerability___(Delay/Time Response)   ' + data['url']+'           '+data['body'])

                                continue

                        else:  # put 修改？
                            con_put = requests.put(url=data['url'], headers=data['headers'], data=data['body'],
                                                   verify=False).text
                            htm_list.append(con_put)
                            flag = bool(re.findall(reg, con_put))
                            flag_list.append(flag)
                            if flag:
                                print('exist SQL Vulnerability___(Regular matching)  ' + data['url'])
                                self.output_data('exist SQL Vulnerability___(Regular matching)  ' + data['url'])
                                continue

        # print(htm_list)
        # 基于内容相似度匹配--鬼麦子
        t = self.Text_comparison(htm_list)

        flag_list.append(bool(t))  # 文本相似度的True&False

        for vul_flag in t:
            if 'GET' in data['method']:
                print('exist SQL Vulnerability___(Text comparison)  ' + datalist[vul_flag])
                self.output_data('exist SQL Vulnerability___(Text comparison)  ' + datalist[vul_flag])
                continue
            else:
                print('exist SQL Vulnerability___(Text comparison)  ' + datalist[vul_flag]+'           '+data['body'])
                self.output_data('exist SQL Vulnerability___(Text comparison)  ' + datalist[vul_flag]+'           '+data['body'])
                continue

        # print(flag_list)

        if True not in flag_list and kill != 0:

            # 当所有常规扫描后的结果没有检测到异常True，将自动开启bypass请求
            self.bypass_waf()  # 死循环, 设置全局标志kill，执行过scan(1)后kill变0
            print('调用了bypasswaf请求')


        return flag_list

    def bypass_waf(self):
        self.scan(1)

    def output_data(self, i):
        with open('vul_sql.txt', "a", encoding='utf-8') as f:
            f.write(i + "\n")


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


def listen():
    path = os.getcwd().replace('\\', '/') + '/export_json'
    monitor = DirMonitor(path)
    monitor.start()
    print("-------------------------Listening-------------------------")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()


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


if __name__ == '__main__':
    # 监听模式
    # listen()
    # 单次扫描模式
    scan = process_http_request()
    scan.scan()
