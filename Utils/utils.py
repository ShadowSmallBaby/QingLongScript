import pathlib
import random
import hashlib
import yaml
import time


def random_sign(mask: str, figure: int) -> str:
    sign = ''
    while len(sign) < figure:
        rIndex = random.randint(0, len(mask) - 1)
        sign += mask[rIndex]
    return sign


# 生成时间戳
def create_timestamp(figure: int = 10) -> str:
    timestamp = time.time()
    power = figure - 10
    return str(int(timestamp * (10 ** power)))


# MD5加密
def md5_crypto(text: str, short: bool = False, upper: bool = True, coding: str = 'utf8') -> str:
    ciphertext = hashlib.md5(text.encode(coding)).hexdigest()
    if short:
        ciphertext = ciphertext[8:-8]
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
