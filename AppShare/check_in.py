#!/usr/bin/python3
# -- coding: utf-8 --
"""
new Env('AppShare签到')
cron: 0 8 0 * * *
Author       : SmallBaby
Date         : 2023-01-09 09:00:00
LastEditTime : 2023-01-10 13:00:00
FilePath     : QingLongScript/AppShare/check_in.py
Description  : 脚本可进行AppShare自动签到,使用前请在配置文件添加账号信息(uid 和 password)
"""

from datetime import datetime
import requests
import threading
import sys

sys.path.append('../')
try:
    from Utils import utils, notify
except Exception as err:  # 异常捕捉
    print(f'{err}\n加载工具服务失败~\n')

api = {
    'login': '/v2/login',
    'sign': '/user/v1/daySign'
}


class AppShare:
    def __init__(self, uid, password, deviceId):
        self.uid = uid
        self.password = utils.md5_crypto(password)
        self.oaid = utils.md5_crypto(deviceId)
        self.headers = get_header()
        self.msg = f'账号"{self.uid}"信息:\n'

    def login(self):
        params = {
            'oaid': self.oaid,
            'account': self.uid,
            'password': self.password,
            'childDevice': 'false',
        }
        params['sign'] = get_sign(params)
        res = requests.get(f'{host}{api.get("login")}', params=params).json()
        isSuccess = res.get('code', 400) == 100
        msg = '登录成功\n' if isSuccess else '登录失败,请稍后重试\n'
        self.msg += msg
        print(f'账号{self.uid}:{msg}')
        return isSuccess

    def sign(self):
        params = {
            'oaid': self.oaid,
        }
        params['sign'] = get_sign(params)
        res = requests.get(f'{host}{api.get("sign")}', params=params).json()
        msg = '签到失败,请稍后重试'
        if res.get('code', 400) == 100:
            data = res.get("data", {})
            msg = f'{data.get("message")}: {data.get("count")}\n'
        print(res)
        self.msg += msg
        print(f'账号{self.uid}:{msg}')

    def main(self):
        if self.login():
            self.sign()
        # notify.send('AppShare消息推送', self.msg)


# 获取header
def get_header():
    headers = {
        'accept-encoding': 'gzip',
        'user-agent': 'okhttp/4.10.0'
    }
    return headers


def get_sign(params):
    sign = ''
    datatime = datetime.now().strftime('%Y%m%d%H%M')
    for value in params.values():
        sign += value
    sign += datatime
    return utils.md5_crypto(sign)


# 生成随机deviceId
def get_device_id():
    mask = '0123456789abcdefghijklmnopqrstuvwxyz'
    return utils.random_sign(mask, 16)


def run_threading(uid, password, deviceId):
    AppShare(uid, str(password), deviceId).main()


if __name__ == '__main__':
    threadList = []
    config = utils.read_yaml()
    print(f'当前配置版本: {config.get("version")}')
    host = config.get('host')
    userList = config.get('accounts')
    for user in userList:
        if user.get('deviceId') is None:
            user['deviceId'] = get_device_id()
            utils.write_yaml(config)
        thread = threading.Thread(target=run_threading, kwargs=user)
        threadList.append(thread)
    for thread in threadList:
        thread.start()
        thread.join()
