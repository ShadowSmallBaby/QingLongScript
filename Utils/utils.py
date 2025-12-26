import base64
from os import environ
from sys import stdout
from datetime import datetime, date, timedelta
from random import randint, uniform, choices
import pathlib
import hashlib
import uuid
import yaml
import time
import json
import re

all_print_list = []


# 生成sign签名
def random_sign(mask: str, figure: int) -> str:
  sign = ''
  while len(sign) < figure:
    r_index = randint(0, len(mask) - 1)
    sign += mask[r_index]
  return sign


# 计算acw_sc__v2 cookie值
def calculate_acw_sc__v2(waf_text: str, c1: str = '4e7c9bda13f58602', prefix: str = '197d84838') -> str | None:
  match = re.search(r"var arg1='([a-f0-9]+)'", waf_text)
  if match:
    arg1 = match.group(1)
  else:
    return None
  try:
    e = list(arg1[:40])
    b = (len(e) + 7) // 8
    _e = [e[j * b + i] for i in range(b) for j in range(8) if j * b + i < len(e)]
    acw_sc__v2 = ''.join([c1[int(c, 16)] for c in _e])
    r_str = ''.join(choices('0123456789abcdef', k=10))
    return f"{prefix}-{acw_sc__v2}{r_str}"
  except Exception as e:
    print(f'Cookie计算失败: {e}')
    return None


# 随机睡眠(精度)
def random_uni_sleep(start: float, end: float):
  sleep_time = uniform(start, end)
  time.sleep(sleep_time)


# 获取当前格式化日期
def format_now_date(fmt: str) -> str:
  return date.today().strftime(fmt)


# 获取当前格式化时间
def format_now_datetime(fmt: str) -> str:
  return datetime.now().strftime(fmt)


# 格式化时间
def format_datetime(fmt: str, t) -> str:
  return time.strftime(fmt, t)


# 生成时间戳
def create_timestamp(figure: int = 10) -> str:
  timestamp = time.time()
  power = figure - 10
  return str(int(timestamp * (10 ** power)))


# 获取uuid
def create_uuid(ver: str = 'v4', namespace: uuid.UUID = uuid.UUID, name: str = '') -> str:
  if ver == 'v4':
    return str(uuid.uuid4())
  elif ver == 'v3':
    return str(uuid.uuid3(namespace, name))
  elif ver == 'v5':
    return str(uuid.uuid5(namespace, name))
  else:
    return ''


# MD5加密
def md5_crypto(text: str, short: bool = False, upper: bool = True, coding: str = 'utf8') -> str:
  ciphertext = hashlib.md5(str(text).encode(coding)).hexdigest()
  if short:
    ciphertext = ciphertext[8:-8]
  return ciphertext.upper() if upper else ciphertext


# SHA256加密
def sha256_crypto(text: str, upper: bool = False, coding: str = 'utf8') -> str:
  ciphertext = hashlib.sha256(str(text).encode(coding)).hexdigest()
  return ciphertext.upper() if upper else ciphertext


# 读取yaml文件
def read_yaml(path: str = 'config.yaml') -> dict:
  with open(pathlib.Path(path), 'rb') as stream:
    return yaml.safe_load(stream)


# 读取多文档yaml文件
def read_multiple_yaml(path: str = 'config.yaml') -> list:
  arr = []
  with open(pathlib.Path(path), 'rb') as stream:
    for el in yaml.safe_load_all(stream):
      arr.append(el)
  return arr


# 写入yaml文件
def write_yaml(obj: dict, path: str = 'config.yaml'):
  with open(pathlib.Path(path), 'w') as stream:
    return yaml.dump(obj, stream)


# 请求URL queryParams 转Python Dict
def format_params(url: str) -> dict:
  params = {}
  query = url.split('?')[1].split('&')
  for kv in query:
    key = kv.split('=')[0]
    value = kv.split('=')[1]
    params.update({key: value})
  return params


# 字典转字符串
def dict_to_str(dict_obj: dict, joint: str = '=', sep: str = '', sort: bool = False, ) -> str:
  dict_str = ''
  keys = sorted(dict_obj.keys()) if sort else dict_obj.keys()
  for key in keys:
    dict_str += f'{key}{joint}{dict_obj[key]}{sep}'
  return dict_str


def complete_crypto_key(key: str) -> str:
  return f'-----BEGIN PUBLIC KEY-----\n{key}\n-----END PUBLIC KEY-----'


# 修改print方法及时输出
def print_now(content):
  print(content)
  stdout.flush()


# 随机休眠时长 若为0时区 TimeZone为真
def random_sleep(min_time=300, max_time=5400, time_zone=True):
  random_time = randint(min_time, max_time)
  print_now(f"随机等待{random_time}秒")
  time.sleep(random_time)
  now_time = (datetime.now() + timedelta(hours=8)).__format__("%Y-%m-%d %H:%M:%S")
  if time_zone:
    now_time = (datetime.now()).__format__("%Y-%m-%d %H:%M:%S")
  print_now(f"等待结束.开始执行 现在时间是------{now_time} ------------")


# 读取环境变量
def get_environ(key, default='', output=True):
  def no_read():
    if output:
      print_now(f"未填写环境变量 {key} 请添加")
    return default

  return environ.get(key) if environ.get(key) else no_read()


# Base64解码
def base64_decode(text: str, str_flag=True, encoding='utf8') -> str | bytes:
  decoded_bytes = base64.b64decode(text)
  return decoded_bytes.decode(encoding) if str_flag else decoded_bytes


def fn_print(*args, sep=' ', end='\n', **kwargs):
  output = ""
  # 构建输出字符串
  for index, arg in enumerate(args):
    if index == len(args) - 1:
      output += str(arg)
      continue
    output += str(arg) + sep
  output = output + end
  all_print_list.append(output)
  # 调用内置的 print 函数打印字符串
  print(*args, sep=sep, end=end, **kwargs)


# 解析 JWT 的 payload 部分
def decode_jwt_payload(token: str) -> dict | None:
  if not token:
    return None
  try:
    parts = token.split('.')
    if len(parts) != 3:
      return None
    payload_b64 = parts[1]
    # 补全 base64 padding
    payload_b64 += '=' * (4 - len(payload_b64) % 4)
    # URL-safe base64 解码
    payload_b64 = payload_b64.replace('-', '+').replace('_', '/')
    payload_json = base64.b64decode(payload_b64)
    return json.loads(payload_json)
  except Exception:
    return None


# 去除 HTML 标签
def strip_html_tags(html: str) -> str:
  if not html:
    return ""
  return re.sub(r'<[^>]+>', '', html).strip()
