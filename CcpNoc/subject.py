#!/usr/bin/python3
# -- coding: utf-8 --
"""
new Env('CCP NOC指导教师刷课')
cron: 0 8-22 0 * * *
Author       : SmallBaby
Date         : 2023-02-11 09:00:00
LastEditTime : 2023-02-15 16:00:00
FilePath     : QingLongScript/CcpNoc/subject.py
Description  : 脚本可进行NOC指导教师刷课,使用前请在配置文件添加账号信息(phone 和 password)
"""
from bs4 import BeautifulSoup
import threading
import requests
import sys

sys.path.append('../')
try:
    from Utils import utils
except Exception as err:  # 异常捕捉
    print(f'{err}\n加载工具服务失败~\n')


def get_header():
    return {
        'accept': 'application/json, text/javascript, */*; q=0.01',
        'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'cache-control': 'no-cache',
        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'pragma': 'no-cache',
        'x-requested-with': 'XMLHttpRequest',
        'user-agent': userAgent
    }


def format_time(timeStr):
    [h, m] = timeStr.split(':')
    return int(h) * 3600 + int(m) * 60


class Noc:
    def __init__(self, idcard, pwd):
        self.idcard = idcard
        self.pwd = pwd
        self.headers = get_header()
        self.get_cookie()
        self.courseList = self.get_user_course()

    def get_cookie(self):
        cookie = self.do_login()
        self.headers['cookie'] = cookie

    def do_login(self):
        self.headers['referrer'] = f'{host}/Home/Login'
        data = {
            'idcard': self.idcard,
            'pwd': self.pwd
        }
        res = requests.post(f'{host}/Home/SubmitLogin', headers=self.headers, data=data)
        isSuccess = res.json().get('Result')
        if isSuccess:
            return res.headers.get('Set-Cookie').split(';', 1)[0]
        else:
            print(f'账号{self.idcard}登录失败:{res.json().get("Msg")},程序退出!')
            exit(0)

    def get_user_course(self, page=1, size=9):
        self.headers['referrer'] = f'{host}/User/Course'
        data = {
            'page': page,
            'size': size
        }
        res = requests.post(f'{host}/User/GetMemberCoursePage', headers=self.headers, data=data).json()
        exCourseList = res.get('Data')[0].get('ExMemberCourseList')
        return exCourseList if len(exCourseList) > 0 else []

    def send_lesson(self, lesson, params):
        self.headers['referrer'] = f'{host}/Course/Lesson?cid={params.get("cid")}&lid={params.get("lid")}'
        data = {
            'lesson': lesson
        }
        res = requests.post(f'{host}/Course/Lessoned', headers=self.headers, data=data)
        if res.status_code == 200:
            print('初始化完成' if lesson == 0 else '上报完成')
            return True
        else:
            print(f'send_lesson: 请求失败, lesson: {lesson}')
            return False

    def send_increase_duration(self, params):
        self.headers['referrer'] = f'{host}/Course/Lesson?cid={params.get("cid")}&lid={params.get("lid")}'
        data = {
            'id': int(params.get('lid')),
            'duration': 10
        }
        res = requests.post(f'{host}/Course/IncreaseDuration', headers=self.headers, data=data)
        if res.status_code == 200:
            print(f'{params.get("name")}视频观看10s, 上报完成')
            return True
        else:
            print(f'send_increase_duration: 请求失败')
            return False

    def get_course_index(self, cid):
        self.headers['referrer'] = f'{host}/User/Course'
        params = {'id': cid}
        res = requests.get(f'{host}/Course/Index', headers=self.headers, params=params)
        htmlStr = res.text
        html = BeautifulSoup(htmlStr, 'html.parser')
        subjectList = []
        for target in html.select_one('.catList').select('a'):
            href = target.get('href')
            if 'Lesson' in href and 'cid' in href and 'lid' in href:
                subObj = {
                    **utils.format_params(href),
                    'name': target.select('div > span')[0].text.strip(),
                    'percent': int(target.select_one('.layui-progress-bar').get('lay-percent').replace('%', '')),
                    'subTime': format_time(target.select('div > span')[1].text)
                }
                subjectList.append(subObj)

        return subjectList if len(subjectList) > 0 else []

    def main(self):
        for subject in self.courseList:
            if subject.get('ExProgress') == 100:
                print(f'{subject.get("ExCcpCourseName")}进度已完成,跳过')
                continue
            print(f'{subject.get("ExCcpCourseName")}进度{subject.get("ExProgress")}%,开始刷课')
            videoList = self.get_course_index(subject.get('CcpCourseID'))
            for node in videoList:
                if node.get('percent') == 100:
                    print(f'{subject.get("ExCcpCourseName")}中<{node.get("name")}>进度已完成,跳过')
                if self.send_lesson(0, node):
                    lookTime = node.get('subTime') * node.get('percent') / 100
                    while node.get('subTime') > lookTime:
                        threads = []
                        remainingTime = node.get('subTime') - lookTime
                        rateTime = 10 if remainingTime >= 10 else remainingTime
                        lessonThread = threading.Timer(8, self.send_lesson, args=(1, node))
                        increaseThread = threading.Timer(rateTime, self.send_increase_duration, args=(node,))
                        threads.append(lessonThread)
                        threads.append(increaseThread)
                        for t in threads:
                            t.start()
                            t.join()
                        lookTime += rateTime


def run_threading(phone, password):
    Noc(phone, password).main()


if __name__ == '__main__':
    threadList = []
    config = utils.read_yaml()
    print(f'当前配置版本: {config.get("version")}')
    host = config.get('host')
    userAgent = config.get('userAgent')
    userList = config.get('accounts')
    for user in userList:
        thread = threading.Thread(target=run_threading, kwargs=user)
        threadList.append(thread)
    for thread in threadList:
        thread.start()
        thread.join()
