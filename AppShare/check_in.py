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
    'sign': '/user/v1/daySign',
    'userInfo': '/user/v1/fragmentMeData',
    'referToken': '/user/login/v1/launchApp2'
}


class AppShare:
    def __init__(self, userInfo):
        self.uid = userInfo.get('uid')
        self.password = utils.md5_crypto(userInfo.get('password'))
        self.oaid = utils.md5_crypto(userInfo.get('deviceId'))
        self.headers = get_header()
        self.userInfo = userInfo
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
        if isSuccess:
            self.get_info()
        self.msg += msg
        print(f'账号{self.uid}:{msg}')
        return isSuccess

    def get_info(self):
        params = {
            'oaid': self.oaid
        }
        params['sign'] = get_sign(params)
        res = requests.get(f'{host}{api.get("userInfo")}', params=params).json()
        isSuccess = res.get('code', 400) == 100
        if isSuccess:
            self.userInfo['pushDeviceToken'] = res.get('data').get('userConfig').get('pushDeviceToken')
        print(f'账号{self.uid}信息:{res}')

    def refer_token(self):
        params = {
            'oaid': self.oaid,
            'versionCode': versionCode,
            'deviceSdk': deviceSdk,
            'pushDeviceToken': self.userInfo.get('pushDeviceToken'),
        }
        params['sign'] = get_sign(params)
        params.setdefault('deviceApi', deviceApi)
        res = requests.get(f'{host}{api.get("referToken")}', params=params).json()
        isSuccess = res.get('code', 400) == 100
        if isSuccess:
            self.get_info()
        msg = f'Token刷新: {res.get("message")}\n'
        self.msg += msg
        print(f'账号{self.uid}:{msg}')
        return isSuccess

    def check_in(self):
        params = {
            'oaid': self.oaid,
        }
        params['sign'] = get_sign(params)
        res = requests.get(f'{host}{api.get("sign")}', params=params).json()
        msg = '签到失败,请稍后重试'
        if res.get('code', 400) == 100:
            data = res.get("data", {})
            msg = f'签到成功: {data.get("count")}\n'
        print(res)
        self.msg += msg
        print(f'账号{self.uid}:{msg}')

    def main(self):
        isSuccess = self.login() if self.userInfo.get('pushDeviceToken') is None else self.refer_token()
        if isSuccess:
            self.check_in()
        notify.send('AppShare消息推送', self.msg)


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
        sign += str(value)
    sign += datatime
    return utils.md5_crypto(sign)


# 生成随机deviceId
def get_device_id():
    mask = '0123456789abcdefghijklmnopqrstuvwxyz'
    return utils.random_sign(mask, 16)


def run_threading(userInfo):
    AppShare(userInfo).main()


if __name__ == '__main__':
    threadList = []
    config = utils.read_yaml()
    print(f'当前配置版本: {config.get("version")}')
    host = config.get('host')
    deviceSdk = config.get('deviceSdk')
    deviceApi = config.get('deviceApi')
    versionCode = config.get('versionCode')
    userList = config.get('accounts')
    for user in userList:
        if user.get('deviceId') is None:
            user['deviceId'] = get_device_id()
        thread = threading.Thread(target=run_threading, args=(user,))
        threadList.append(thread)
    for thread in threadList:
        thread.start()
        thread.join()
    utils.write_yaml(config)
