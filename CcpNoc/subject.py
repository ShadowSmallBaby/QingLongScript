import threading
import requests
from bs4 import BeautifulSoup

host = 'http://ccp.noc.net.cn'
cookie = ''
videoList = []
courseList = []


def get_header():
    return {
        'accept': 'application/json, text/javascript, */*; q=0.01',
        'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'cache-control': 'no-cache',
        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'pragma': 'no-cache',
        'x-requested-with': 'XMLHttpRequest',
        'cookie': cookie,
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36'
    }


def send_lesson(lesson, params):
    headers = {
        **get_header(),
        'referrer': f'{host}/Course/Lesson?cid={params.get("cid")}&lid={params.get("lid")}',
    }
    data = {
        'lesson': lesson
    }
    res = requests.post(f'{host}/Course/Lessoned', headers=headers, data=data)
    if res.status_code == 200:
        print('初始化完成' if lesson == 0 else '上报完成')
        return True
    else:
        print(f'send_lesson: 请求失败, lesson: {lesson}')
        return False


def send_increase_duration(params):
    headers = {
        **get_header(),
        'referrer': f'{host}/Course/Lesson?cid={params.get("cid")}&lid={params.get("lid")}',
    }
    data = {
        'id': int(params.get('lid')),
        'duration': 10
    }
    res = requests.post(f'{host}/Course/IncreaseDuration', headers=headers, data=data)
    if res.status_code == 200:
        print(f'{params.get("name")}视频观看10s, 上报完成')
        return True
    else:
        print(f'send_increase_duration: 请求失败')
        return False


def get_course_index(cid):
    headers = {
        **get_header(),
        'referrer': f'{host}/User/Course',
    }
    params = {'id': cid}
    res = requests.get(f'{host}/Course/Index', headers=headers, params=params)
    htmlStr = res.text
    html = BeautifulSoup(htmlStr, 'html.parser')
    subjectList = []
    for target in html.select_one('.catList').select('a'):
        href = target.get('href')
        if 'Lesson' in href and 'cid' in href and 'lid' in href:
            subObj = {
                **format_params(href),
                'name': target.select('div > span')[0].text.strip(),
                'percent': int(target.select_one('.layui-progress-bar').get('lay-percent').replace('%', '')),
                'subTime': format_time(target.select('div > span')[1].text)
            }
            subjectList.append(subObj)

    return subjectList if len(subjectList) > 0 else []


def get_user_course(page=1, size=9):
    headers = {
        **get_header(),
        'referrer': f'{host}/User/Course',
    }
    data = {
        'page': page,
        'size': size
    }
    res = requests.post(f'{host}/User/GetMemberCoursePage', headers=headers, data=data).json()
    exCourseList = res.get('Data')[0].get('ExMemberCourseList')
    return exCourseList if len(exCourseList) > 0 else []


def format_params(url):
    params = {}
    query = url.split('?')[1].split('&')
    for kv in query:
        key = kv.split('=')[0]
        value = kv.split('=')[1]
        params.update({key: value})
    return params


def format_time(timeStr):
    [h, m] = timeStr.split(':')
    return int(h) * 3600 + int(m) * 60


if __name__ == '__main__':
    courseList = get_user_course()
    for subject in courseList:
        if subject.get('ExProgress') == 100:
            print(f'{subject.get("ExCcpCourseName")}进度已完成,跳过')
            continue
        print(f'{subject.get("ExCcpCourseName")}进度{subject.get("ExProgress")}%,开始刷课')
        videoList = get_course_index(subject.get('CcpCourseID'))
        for node in videoList:
            if node.get('percent') == 100:
                print(f'{subject.get("ExCcpCourseName")}中<{node.get("name")}>进度已完成,跳过')
            if send_lesson(0, node):
                lookTime = node.get('subTime') * node.get('percent') / 100
                while node.get('subTime') > lookTime:
                    threadList = []
                    remainingTime = node.get('subTime') - lookTime
                    rateTime = 10 if remainingTime >= 10 else remainingTime
                    lessonThread = threading.Timer(8, send_lesson, args=(1, node))
                    increaseThread = threading.Timer(rateTime, send_increase_duration, args=(node,))
                    threadList.append(lessonThread)
                    threadList.append(increaseThread)
                    for thread in threadList:
                        thread.start()
                        thread.join()
                    lookTime += rateTime
