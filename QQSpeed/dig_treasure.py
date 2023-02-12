#!/usr/bin/python3
# -- coding: utf-8 --
"""
new Env('掌上飞车寻宝')
cron: 0 2 0,12 * * *
Author       : SmallBaby
Date         : 2022-12-19 09:00:00
LastEditTime : 2023-01-09 13:00:00
FilePath     : QingLongScript/QQSpeed/dig_treasure.py
Description  :
添加环境变量QQ_SPEED_COOKIE、QQ_SPEED_REFERER，多账号用回车换行分开
值分别是cookie和referer
"""
import json
import random
import threading
import time
from os import environ
from urllib.parse import unquote
from bs4 import BeautifulSoup
import requests
import re
import sys

sys.path.append('../')

try:
    import Utils.notify
except Exception as err:  # 异常捕捉
    print(f'{err}\n加载通知服务失败~\n')


# 测试用环境变量
# environ['QQ_SPEED_COOKIE'] = ''
# environ['QQ_SPEED_REFERER'] = ''


class DigTreasure:
    def __init__(self, cookie, referer, star_id=0):
        self.cookie = cookie
        self.referer = f'{baseHost}?{referer.split("?")[1]}'
        self.headers = get_headers(self.cookie, self.referer)
        self.userInfo, self.mapInfo = self.get_treasure_index()
        self.userData = self.get_user_data()
        self.todayTimes = int(self.userInfo.get('todayTimes'))
        self.mapEvent = self.get_map_event(star_id)
        self.msg = f'账号{self.userData.get("roleId")}寻宝结果:\n'

    def get_user_data(self):
        user_data = {}
        for kv in self.referer.split('?')[1].split('&'):
            if len(kv) > 0:
                kvArr = kv.split('=')
                key = kvArr[0]
                value = unquote(kvArr[1]) if len(kvArr) == 2 else ''
                user_data.update({key: value})
        return user_data

    # 获取寻宝地图
    def get_map_event(self, star_id):
        starId = mapId = star_id
        if starId == 0:
            # 获取startId
            starInfo = self.userInfo.get('starInfo')
            starKeys = list(starInfo.keys())
            starKeys.reverse()
            for star in starKeys:
                if starInfo.get(star) == 1:
                    starId = star
                    break

        # 获取mapId
        maps = self.mapInfo.get(starId)
        for mapObj in maps:
            if mapObj.get('isdaji') == 1:
                mapId = mapObj.get('id')
                break

        return {
            'starId': int(starId),
            'mapId': mapId,
            'type': 1 if self.userInfo.get('vip_flag') == 0 else 2
        }

    # 获取userInfo / mapInfo
    def get_treasure_index(self):
        headers = self.headers
        res = requests.get(self.referer, headers=headers)
        htmlStr = res.text
        html = BeautifulSoup(htmlStr, 'html.parser')
        pattern = re.compile(r"eval\('\((.*?)\)'\);", re.MULTILINE | re.DOTALL)
        evalScript = html.find('script', text=pattern)
        userInfo = json.loads(re.findall(pattern, evalScript.text)[0])
        mapInfo = json.loads(re.findall(pattern, evalScript.text)[1])
        return userInfo, mapInfo

    # 鉴权汇报
    def login_analysis(self, eid=10272):
        headers = self.headers
        url = 'https://bang.qq.com/login/analysis'
        params = {
            'mid': 10,
            'eid': eid,
            'game': 'speed',
            'uin': self.userData.get('uin'),
            'openid': self.userData.get('appOpenid'),
            'userid': self.userData.get('userId'),
            'surl': '',
            'durl': '/app/speed/treasure/index',
            'qq': self.userData.get('roleId'),
            'aid': self.userData.get('userId'),
            'from': 'mobile',
            'ref': ''
        }
        res = requests.get(url, headers=headers, params=params).json()
        return res.get('res') == 0

    # 开始寻宝
    def do_dig_treasure(self, action='start'):
        headers = self.headers
        url = f'https://bang.qq.com/app/speed/treasure/ajax/{action}DigTreasure'
        data = {
            'game': 'speed',
            'mapId': self.mapEvent.get('mapId'),
            'starId': self.mapEvent.get('starId'),
            'type': self.mapEvent.get('type'),
            'serverId': self.userData.get('serverId'),
            'areaId': self.userData.get('areaId'),
            'roleId': self.userData.get('roleId'),
            'userId': self.userData.get('userId'),
            'appOpenid': self.userData.get('appOpenid'),
            'uin': self.userData.get('uin'),
            'token': self.userData.get('token'),
        }
        res = requests.post(url, headers=headers, data=data).json()
        isSuccess = res.get('res') == 0
        if isSuccess:
            isSuccess = self.login_analysis(10273 if action == 'start' else 10274)
            if isSuccess and action == 'end':
                self.todayTimes += 1
                self.get_amesvr_info()
                self.get_amesvr_info(1)
        return isSuccess

    # AMS活动获奖详情
    def get_amesvr_info(self, action=0):
        flowIdMap = {
            # starId: [M, B]
            '1': [856152, 856155],
            '2': [856155, 856157],
            '3': [856158, 856159],
            '4': [856160, 856161],
            '5': [856162, 856163],
            '6': [856164, 856165],
        }
        # 参数获取: https://apps.game.qq.com/comm-htdocs/js/ams/actDesc/228/468228/act.desc.js
        headers = get_headers(self.cookie, 'https://bang.qq.com')
        url = 'https://act.game.qq.com/ams/ame/amesvr'
        flowId = flowIdMap.get(str(self.mapEvent.get('starId')))[action]
        params = {
            'ameVersion': 0.3,
            'sServiceType': 'bb',
            'iActivityId': '468228',
            'sServiceDepartment': 'xinyue',
            'sSDID': '42a6eb3c5e2fec32f90c3b085368457a',
            'sMiloTag': f'AMS-MILO-468228-{flowId}-{self.userData.get("appOpenid")}-{int(time.time() * 1000)}-{get_random_sign()}',
            '_': int(time.time() * 1000)
        }
        data = {
            'appid': self.userData.get('appid'),
            'gameId': '',
            'sArea': self.userData.get('areaId'),
            'iSex': '',
            'sRoleId': self.userData.get('roleId'),
            'iGender': '',
            'openid': '',
            'accessToken': self.userData.get('accessToken'),
            'sPartition': self.userData.get('areaId'),
            'sAreaName': self.userData.get('areaName'),
            'sRoleName': self.userData.get('roleName'),
            'starid': self.mapEvent.get('starId'),
            'mapid': self.mapEvent.get('mapId'),
            'xhr': 1,
            'sServiceType': 'bb',
            'objCustomMsg': '',
            'areaname': '',
            'roleid': '',
            'rolelevel': '',
            'rolename': '',
            'areaid': '',
            'iActivityId': '468228',
            'iFlowId': flowId,
            'sServiceDepartment': 'xinyue',
            # 参数获取 FlowEngine: https://ossweb-img.qq.com/images/js/mobile_bundle/ams/flowengine.js?1662566021380
            # MILO地址: https://ossweb-img.qq.com/images/js/mobile_bundle/milo.js
            # 参数获取 AMSEngine: https://ossweb-img.qq.com/images/js/mobile_bundle/ams/engine.js?1662566021380
            # 参数获取 EAS: https://ossweb-img.qq.com/images/js/eas/eas.js
            'g_tk': get_ame_token(self.userData.get('skey', 'a1b2c3')),
            'e_code': self.userData.get('e_code', 0),
            'g_code': self.userData.get('g_code', 0),
            'eas_url': get_eas_url(self.referer),
            'eas_refer': get_eas_refer()
        }
        res = requests.post(url, headers=headers, params=params, data=data)
        res.encoding = res.apparent_encoding
        res = res.json()
        # print(f'抽奖详情: {res}\n')
        if int(res.get('ret')) == 0:
            packageName = res.get('modRet').get('sPackageName')
            if action == 0 and len(packageName) > 0:
                self.set_speed_actlb_info(res.get('modRet').get('iPackageId'))
            print(f'{self.userData.get("roleId")}寻宝结束,获得了{packageName}\n')
            print(f'{res.get("modRet").get("sMsg")}\n')
            self.msg += f'第{self.todayTimes}次寻宝结束,获得了{packageName}\n'
        else:
            print(f'{self.userData.get("roleId")}: {res.get("msg")}\n')

    # 设置寻宝信息
    def set_speed_actlb_info(self, package_id):
        headers = self.headers
        packageIds = ['3226026', '3226028', '3226073', '3226115', '3226119', '3226139', '3226140', '3226141', '3226183',
                      '3226184', '3226208', '3226209', '3226213', '3226226', '3226227', '3226225', '3226245']
        url = 'https://bang.qq.com/app/activity/setSpeedActlbInfo'
        data = {
            'uin': self.userData.get('uin'),
            'lbId': package_id,
            'rolename': self.userData.get('rolename'),
            'userId': self.userData.get('userId'),
            'token': self.userData.get('token'),
            'gameId': self.userData.get('gameId')
        }
        if package_id in packageIds:
            res = requests.post(url, headers=headers, data=data).json()
            print(res)

    def main(self):
        userId = self.userData.get('roleId')
        print(f'线程-{userId} 创建成功\n')
        todayCanTimes = int(self.userInfo.get('todaycanTimes'))
        isLogin = self.login_analysis()
        userDelay = 10 if self.mapEvent.get('type') == 2 else 10 * 60
        for idx in range(todayCanTimes - self.todayTimes):
            print(f'{userId}今日寻宝总次数:{todayCanTimes},现在进行第{self.todayTimes + 1}次寻宝\n')
            if isLogin:
                isStart = self.do_dig_treasure()
                print(f'{userId}寻宝已经开始,将在{userDelay}秒后结束寻宝\n')
                if isStart:
                    threadEnd = threading.Timer(userDelay, DigTreasure.do_dig_treasure, args=(self, 'end'))
                    threadEnd.start()
                    threadEnd.join()
        if self.todayTimes == todayCanTimes:
            print(f'{userId}今日寻宝已结束,共寻宝{todayCanTimes}次\n')
            self.msg += f'{userId}今日寻宝已结束,共寻宝{todayCanTimes}次\n'
            try:
                notify.send('掌上飞车寻宝', self.msg)
            except Exception as err:  # 异常捕捉
                print(f'{err}\n加载通知服务失败~\n')
        time.sleep(5)


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


# 获取Host并格式化
def get_eas_url(referer):
    if isinstance(referer, str):
        referer = referer.lower()
        if referer.find('?') != -1:
            referer = referer[:referer.find('?')]
        if referer.find('#') != -1:
            referer = referer[:referer.find('#')]
        strArr = referer.split('/')
        if len(strArr[-1]) > 0 and strArr[-1].find('.shtml') == -1 and strArr[-1].find('.html') == -1 and strArr[
            -1].find('.htm') == -1 and strArr[-1].find('.php') == -1:
            referer += '/'
        referer = re.compile(r"\\+").sub('/', referer)
        referer = re.compile(r"^https?:/+").sub('http://', referer)
        referer = re.compile(r"^/").sub('http://', referer)
        return referer
    return ''


# 生成G_TK
def get_ame_token(ame_str):
    hashVal = 5381
    for h in range(len(ame_str)):
        hashVal += (hashVal << 5) + ord(ame_str[h])
    return hashVal & 2147483647


# 生成EAS referer参数
def get_eas_refer(referer=''):
    # 示例: http://noreferrer/?reqid=781b2c57-a30b-4827-8faa-d5cb5e2d6f42&version=26
    easVersion = 26
    easRefer = referer
    if len(easRefer) == 0:
        easRefer = 'http://noreferrer/'
    easRefer = get_eas_url(easRefer)
    if easRefer.find('?') == -1:
        return f'{easRefer}?reqid={get_uuid()}&version={easVersion}'
    return f'{easRefer}&reqid={get_uuid()}&version={easVersion}'


# 生成随机sign
def get_random_sign():
    randomMask = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    randomSign = ''
    while len(randomSign) < 6:
        rIndex = random.randint(0, 61)
        randomSign += randomMask[rIndex]
    return randomSign


# 生成UUID
def get_uuid():
    uuidMask = '0123456789abcdef'
    uuid = [''] * 36
    for u in range(36):
        uuid[u] = uuidMask[random.randint(0, 15)]
    uuid[14] = '4'
    uuid[19] = uuidMask[(0 if int(uuid[19], 16) > 9 else int(uuid[19])) & 3 | 8]
    uuid[8] = uuid[13] = uuid[18] = uuid[23] = '-'
    uuid[35] = uuidMask[
        (ord(uuid[0]) + ord(uuid[10]) + ord(uuid[16]) + ord(uuid[22]) + ord(uuid[28])) % len(uuidMask)]
    uuid[34] = uuidMask[((ord(uuid[1]) + ord(uuid[11]) + ord(uuid[17]) + ord(uuid[29])) % len(uuidMask))]
    return ''.join(uuid)


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
    DigTreasure(cookie, referer).main()


if __name__ == '__main__':
    baseHost = 'https://bang.qq.com/app/speed/treasure/index'
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
