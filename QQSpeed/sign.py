#!/usr/bin/python3
# -- coding: utf-8 --
"""
new Env('掌上飞车签到')
cron: 0 0 0 * * *
Author       : SmallBaby
Date         : 2023-01-09 09:00:00
LastEditTime : 2023-01-10 13:00:00
FilePath     : QingLongScript/QQSpeed/sign.py
Description  :
添加环境变量QQ_SPEED_COOKIE、QQ_SPEED_REFERER，多账号用回车换行分开
值分别是cookie和referer
"""
import threading
from datetime import datetime
from bs4 import BeautifulSoup
import requests
from os import environ
import sys
import re
import time

sys.path.append('../')

try:
    import Utils.notify
except Exception as err:  # 异常捕捉
    print(f'{err}\n加载通知服务失败~\n')

# 测试用环境变量
# environ['QQ_SPEED_COOKIE'] = ''
# environ['QQ_SPEED_REFERER'] = ''


class Sign:
    def __init__(self, cookie, referer):
        self.cookie = cookie
        self.referer = f'{baseHost}?{referer.split("?")[1]}'
        self.headers = get_headers(self.cookie, self.referer)
        self.signInfo, self.benefitsArr, self.signParam = self.get_sign_index()
        self.msg = f'账号{self.signParam.get("params").get("roleId")}签到结果:\n'

    # 获取签到页面
    def get_sign_index(self):
        headers = self.headers
        res = requests.get(self.referer, headers=headers)
        htmlStr = res.text
        html = BeautifulSoup(htmlStr, 'html.parser')
        tabSoupArr = html.select('.evt-tab-panel')
        signSoupArr = tabSoupArr[0]
        benefitsSoupArr = tabSoupArr[1]
        signInfo = {}
        benefitsArr = []

        # 获取每日签到福利signInfo
        for target in signSoupArr.find_all('dl'):
            key = target.select_one('span').text
            signInfo[key] = {
                'giftId': target.select_one('a').get('giftid'),
                'status': target.select_one('a').get('class')[0] == 'received',
                'label': target.select_one('.name').text
            }
        signInfo['user'] = {
            'giftId': signSoupArr.select_one('#signButton').get('giftid'),
            'status': signSoupArr.select_one('#signButton').get('class')[0] == 'btn_signed',
            'label': html.select_one('.cumulative').text,
            'count': int(html.select_one('#my_count').text)
        }

        # 获取特殊福利benefitsArr
        for target in benefitsSoupArr.select('.gift-bag'):
            benefits = {
                'giftId': target.select_one('a').get('giftid'),
                'status': target.select_one('a').get('class')[0] == 'received',
                'datetime': target.select_one('.text2').text,
                'label': f'{target.select_one(".text2").text}: {target.select_one(".name").text}'
            }
            benefitsArr.append(benefits)

        # 获取signParam
        pattern = re.compile(r'var signParam = (\{.*}.*?$).*?var shareInfo', re.MULTILINE | re.DOTALL)
        evalScript = html.find('script', text=pattern)
        signParamStr = re.findall(pattern, evalScript.text)[0]
        signParam = eval(signParamStr, type('js', (dict,), dict(__getitem__=lambda s, n: n))())

        return signInfo, benefitsArr, signParam

    # 开始签到
    def do_sign(self):
        headers = self.headers
        url = f'https://mwegame.qq.com/ams/sign/doSign/{self.signParam.get("type")}'
        params = {
            **self.signParam.get('params'),
            'gift_id': self.signInfo.get('user').get('giftId')
        }
        res = requests.get(url, headers=headers, params=params).json()
        msg = f'{res.get("message", "")}: {res.get("send_result", {}).get("sMsg", "")}\n'
        print(msg)
        self.msg += msg
        return res.get('status') == 1

    # 领取福利
    def get_gift(self, gift_id):
        headers = self.headers
        url = 'https://mwegame.qq.com/ams/send/handle'
        data = {
            **self.signParam.get('params'),
            'gift_id': gift_id
        }
        res = requests.post(url, headers=headers, data=data).json()
        msg = f'{res.get("message", "")}{res.get("data", "")}: {res.get("send_result", {}).get("sMsg", "")}\n'
        print(msg)
        self.msg += msg
        return res.get('status') == 1

    # 鉴权汇报
    def login_analysis(self, eid=10011):
        headers = self.headers
        url = 'https://mwegame.qq.com/login/analysis'
        data = {
            'mid': 10,
            'eid': eid,
            'surl': '',
            'durl': self.referer,
            'qq': self.signParam.get('params').get('roleId'),
            'openid': self.signParam.get('params').get('appOpenid'),
            'game': 'speed',
            'bd': 0,
            'qid': 3,
            'aid': self.signParam.get('params').get('userId'),
            'from': 'mobile',
            'ref': '',
            'encodeOpenId': 0,
            'encodeQQ': 0,
        }
        res = requests.post(url, headers=headers, data=data).json()
        return res.get('res') == 0

    def main(self):
        userId = self.signParam.get('params').get('roleId')
        print(f'线程-{userId} 创建成功\n')
        userSign = self.signInfo.get('user')
        benefits = self.benefitsArr[0]
        isLogin = self.login_analysis()
        if isLogin:
            # 每日签到
            if userSign.get('status'):
                print(userSign.get('label'))
                self.msg += f'{userSign.get("label")}'
            else:
                if self.do_sign():
                    userSign['count'] += 1
                    print(f'本月累计签到 {userSign["count"]} 天\n')
                    self.msg += f'本月累计签到 {userSign["count"]} 天\n'
            # 每日签到福利领取
            for key in self.signInfo.keys():
                if key == 'user':
                    continue
                if int(key) > userSign.get('count'):
                    break
                if not self.signInfo[key].get('status'):
                    self.get_gift(self.signInfo[key].get('giftId'))
                    # 延迟2秒执行，防止频繁
                    time.sleep(2)
            # 特殊福利领取
            if benefits.get('datetime') <= datetime.now().strftime('%m月%d日'):
                self.get_gift(benefits.get('giftId'))
            try:
                notify.send('掌上飞车签到', self.msg)
            except Exception as err:  # 异常捕捉
                print(f'{err}\n加载通知服务失败~\n')


# 构造请求头
def get_headers(cookie='', referer=''):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 11; Redmi K20 Pro Premium Edition Build/RKQ1.200826.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/107.0.5304.105 Mobile Safari/537.36 GH_QQConnect GameHelper_1003/2103040778',
        'Connection': 'keep-alive',
        'Accept': 'application/json',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
    }
    if cookie != '':
        headers['Cookie'] = cookie
    if referer != '':
        if '?' in referer:
            headers['Referer'] = f'{baseHost}?{referer.split("?")[1]}'
        else:
            headers['Referer'] = referer
    return headers


# 读取环境变量并格式化
def get_cookie():
    cookie_arr = get_environ('QQ_SPEED_COOKIE').split('\n')
    referer_arr = get_environ('QQ_SPEED_REFERER').split('\n')
    return cookie_arr, referer_arr


# 封装读取环境变量的方法
def get_environ(key, default=''):
    if len(environ.get(key, '')) == 0:
        print(f'环境变量 {key} 未添加,程序已退出\n')
        exit()
    return environ.get(key, default)


def run_threading(cookie, referer):
    Sign(cookie, referer).main()


if __name__ == '__main__':
    baseHost = 'https://mwegame.qq.com/ams/sign/month/speed'
    cookieArr, refererArr = get_cookie()
    threadArr = []
    for i in range(len(cookieArr)):
        if len(refererArr) < i + 1:
            print('填写了Cookie,但没填写Referer,跳过该账号\n')
            continue
        threadUser = threading.Thread(target=run_threading, args=(cookieArr[i], refererArr[i]))
        threadUser.start()
        threadArr.append(threadUser)
    for i in range(len(cookieArr)):
        threadArr[i].join()
