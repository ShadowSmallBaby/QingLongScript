import sys
import threading
import time
import json
import random
import hashlib
import os
from urllib.parse import quote
from datetime import datetime, timedelta

import requests

sys.path.append('../')
try:
  from Utils import utils, notify
except Exception as err:
  print(f'{err}\n加载工具服务失败~\n')

# 全局缓存数据
_global_cache_data = {}
_cache_file_path = os.path.join(os.path.dirname(__file__), 'svw_cache.json')


# 从JWT解析过期时间
def _get_expire_from_jwt(token):
  if not token:
    return None
  try:
    payload = utils.decode_jwt_payload(token)
    if payload and 'exp' in payload:
      return int(payload['exp'] * 1000)
  except Exception:
    pass
  return None


# 初始化全局缓存（程序启动时调用）
def init_global_cache():
  global _global_cache_data
  try:
    if os.path.exists(_cache_file_path):
      with open(_cache_file_path, 'r', encoding='utf-8') as f:
        _global_cache_data = json.load(f)
    else:
      _global_cache_data = {}
  except (json.JSONDecodeError, ValueError):
    _global_cache_data = {}
  except Exception as e:
    print(f'加载缓存文件失败: {e}')
    _global_cache_data = {}


# 刷新全局缓存到文件（程序结束时调用）
def flush_global_cache():
  global _global_cache_data
  try:
    with open(_cache_file_path, 'w', encoding='utf-8') as f:
      json.dump(_global_cache_data, f, ensure_ascii=False, indent=2)
    print('缓存文件已更新')
  except Exception as e:
    print(f'保存缓存文件失败: {e}')


# 生成x-sign签名
def generate_x_sign(url, method, data=None, params=None, sx_token=None, app_key=None):
  timestamp = utils.create_timestamp(13)
  nonce = str(random.random())[2:]

  r = ""
  if method and method.lower() == "get":
    if params:
      r = "&".join([f"{k}={v}" for k, v in params.items()]) + "&"
    elif "?" in url:
      r = url.split("?")[1] + "&"
  elif method and method.lower() == "post":
    if data:
      r = json.dumps(data) if isinstance(data, dict) else data
    elif params:
      r = "&".join([f"{k}={v}" for k, v in params.items()]) + "&"

  if r == "{}" or r == "":
    r = ""

  if method and method.lower() == "get" and r:
    r = quote(r, safe='')
    replacements = [
      ('%20', '+'), ("'", '%27'), ('!', '%21'),
      ('~', '%7E'), ('(', '%28'), (')', '%29')
    ]
    for old, new in replacements:
      r = r.replace(old, new)

  if sx_token:
    sign_str = r + timestamp + nonce + app_key + sx_token
    sign = hashlib.sha1(sign_str.encode()).hexdigest()
  else:
    sign_str = r + timestamp + nonce + app_key
    sign = hashlib.md5(sign_str.encode()).hexdigest().lower()

  return {
    'x_sign': sign,
    'x_nonce': nonce,
    'x_timestamp': timestamp,
    'x_app_key': app_key
  }


# 生成随机设备ID
def generate_random_device_ids():
  android_version = random.randint(8, 16)
  uuid_hex = utils.create_uuid().replace('-', '')
  random_16 = uuid_hex[8:24]
  app_version = '4.2.6'
  device_model = '23127PN0CC'
  did = f'VW_APP_{device_model}_{uuid_hex}_{android_version}_{app_version}'
  device_id = f'vw{random_16}'
  web_id = f'vw{utils.create_uuid()}'

  return {
    'did': did,
    'device_id': device_id,
    'web_id': web_id
  }


# 从 did 解析设备信息
def parse_device_info_from_did(did):
  parts = did.split('_')
  return {
    'model': parts[2],
    'systemVersion': parts[-2],
    'appVersion': parts[-1],
  }


# ==================== SVW 主类 ====================
class SVW:
  def __init__(self, account, password, did=None, device_id=None, web_id=None, task_whitelist=None, unified_msg=True,
               h5_config=None, app_config=None):
    self.account = str(account)
    self.password = password

    # 消息管理
    self.msg = []
    self.unified_msg = unified_msg
    self.task_whitelist = task_whitelist or []

    # 设备信息初始化：传入 → 缓存 → 随机生成
    user_cache = _global_cache_data.get(self.account, {})
    cached_device = user_cache.get('device_info', {})

    self.did = did or cached_device.get('did') or generate_random_device_ids()['did']
    self.device_id = device_id or cached_device.get('deviceId') or generate_random_device_ids()['device_id']
    self.web_id = web_id or cached_device.get('webId') or generate_random_device_ids()['web_id']

    # 设备认证状态
    self.is_auth = cached_device.get('isAuth', False)

    # Token 相关
    self.id_token = None
    self.server_token = None
    self.refresh_token = None
    self.sx_token = None
    self.user_id = None
    self.idp_id = None

    # H5 和 APP 配置
    self.h5_config = h5_config or {}
    self.app_config = app_config or {}

    self.article_read_done = False

  # 记录消息
  def log(self, message, show_prefix=True):
    prefix = f'[{self.account}] ' if show_prefix else ''
    full_msg = f'{prefix}{message}'

    self.msg.append(full_msg)
    if not self.unified_msg:
      print(full_msg)

  # 输出动作提示
  def log_action(self, action):
    if not self.unified_msg:
      print(f'\n>>> 开始执行: {action}')
    else:
      self.msg.append(f'>>> 开始执行: {action}')

  # ==================== 缓存管理 ====================
  # 检查token是否过期
  def _is_token_expired(self, token_data):
    if not token_data:
      return True

    if isinstance(token_data, str):
      return False

    if isinstance(token_data, dict):
      expire_time = token_data.get('t')
      if expire_time:
        current_time = int(time.time() * 1000)
        return current_time >= expire_time
      return True

    return True

  # 格式化token用于缓存
  def _format_token_for_cache(self, token_value, expires_in=None):
    if expires_in is None:
      return token_value

    # 计算过期时间戳（毫秒）
    expire_time = int(time.time() * 1000) + (expires_in * 1000)

    return {
      'v': token_value,
      't': expire_time
    }

  # 从缓存提取token值
  def _extract_token_value(self, token_data):
    if not token_data:
      return None

    if isinstance(token_data, str):
      return token_data

    if isinstance(token_data, dict):
      if not self._is_token_expired(token_data):
        return token_data.get('v')
      return None

    return None

  # 加载缓存
  def load_cache(self):
    try:
      user_cache = _global_cache_data.get(self.account, {})
      if user_cache:
        id_token_data = user_cache.get('id_token')
        self.id_token = self._extract_token_value(id_token_data)

        server_token_data = user_cache.get('server_token')
        self.server_token = self._extract_token_value(server_token_data)

        self.refresh_token = user_cache.get('refresh_token')

        sx_token_data = user_cache.get('sx_token')
        self.sx_token = self._extract_token_value(sx_token_data)

        self.user_id = user_cache.get('user_id')
        self.idp_id = user_cache.get('idp_id')

        # 判断缓存是否有效：优先检查 server_token，其次检查 id_token
        if self.server_token:
          self.log('从缓存加载Token成功')
          return True
        elif self.id_token:
          self.log('从缓存加载idToken成功（缺少server_token，将自动获取）')
          return True
        else:
          self.log('缓存中的关键token已过期')
          return False
      else:
        self.log('缓存中无该账号信息')
        return False
    except Exception as e:
      self.log(f'加载缓存失败: {e}')
      return False

  # 保存缓存
  def save_cache(self, id_token_expires_in=None, server_token_expires_in=None):
    try:
      # 处理过期时间：如果传入的 expires_in 为 None，从 JWT 解析
      if id_token_expires_in is None and self.id_token:
        id_token_expires_in = _get_expire_from_jwt(self.id_token)
      if server_token_expires_in is None and self.server_token:
        # server_token 可能是 "Bearer xxx" 格式，需要提取 JWT 部分
        token = self.server_token.replace('Bearer ', '') if self.server_token.startswith(
          'Bearer ') else self.server_token
        server_token_expires_in = _get_expire_from_jwt(token)

      # 格式化 token
      id_token_to_save = self._format_token_for_cache(
        self.id_token, id_token_expires_in
      ) if self.id_token else None

      server_token_to_save = self._format_token_for_cache(
        self.server_token, server_token_expires_in
      ) if self.server_token else None

      # 更新全局缓存
      _global_cache_data[self.account] = {
        'id_token': id_token_to_save,
        'server_token': server_token_to_save,
        'refresh_token': self.refresh_token,
        'sx_token': self.sx_token,
        'user_id': self.user_id,
        'idp_id': self.idp_id,
        'device_info': {
          'did': self.did,
          'deviceId': self.device_id,
          'webId': self.web_id,
          'isAuth': self.is_auth
        }
      }

      self.log('Token缓存成功')
      return True
    except Exception as e:
      self.log(f'缓存保存失败: {e}')
      return False

  # ==================== 认证系统 ====================
  # 密码登录
  def pwd_login(self):
    self.log_action('密码登录')

    url = 'https://api.mos.csvw.com/mos/security/api/v1/app/actions/pwdlogin'
    headers = self._build_app_headers()
    body = {
      'brand': 'vw',
      'deviceId': self.did,
      'deviceType': 'android',
      'mobile': self.account,
      'pwd': self.password,
      'scope': 'openid',
      'picContent': '',
      'picTicket': ''
    }

    try:
      res = requests.post(url, headers=headers, json=body).json()
      if res['code'] == '000000':
        self.id_token = res['data']['idToken']
        self.user_id = res['data']['userId']
        id_token_expires_in = res['data'].get('expiresIn')

        # 解析 JWT 获取 idpId
        jwt_payload = utils.decode_jwt_payload(self.id_token)
        if jwt_payload:
          self.idp_id = jwt_payload.get('sub')

        self.log('密码登录成功')
        self.save_cache(id_token_expires_in=id_token_expires_in)
        return True, None, None
      else:
        error_code = res.get('code', 'Unknown')
        error_msg = res.get('description') or res.get('message', '未知错误')
        self.log(f'密码登录失败: Code=[{error_code}], Message={error_msg}')
        return False, error_code, error_msg
    except Exception as e:
      self.log(f'登录异常: {e}')
      return False, None, str(e)

  # 获取短信验证码
  def get_sms_code(self):
    self.log_action('获取短信验证码')

    url = 'https://api.mos.csvw.com/mos/security/api/v1/smsCode/getSmsCode/loginAndRegister'
    headers = self._build_app_headers()
    headers['Content-Type'] = 'application/x-www-form-urlencoded'

    data = {
      'mobile': self.account,
      'type': 'login',
      'brand': 'vw'
    }

    try:
      res = requests.post(url, headers=headers, data=data).json()
      if res['code'] == '000000':
        self.log('验证码发送成功')
        return True
      else:
        self.log(f'获取验证码失败: {res.get("description", "未知错误")}')
        return False
    except Exception as e:
      self.log(f'获取验证码异常: {e}')
      return False

  # 验证码登录
  def sms_login(self, sms_code):
    self.log_action('验证码登录')

    url = 'https://api.mos.csvw.com/mos/security/api/v2/app/actions/loginAndRegister'
    headers = self._build_app_headers()
    body = {
      'brand': 'vw',
      'deviceId': self.did,
      'deviceType': 'android',
      'mobile': self.account,
      'smsCode': sms_code,
      'scope': 'openid',
      'picContent': '',
      'picTicket': '',
      'consentTypeList': 'app_agreement,app_privacy',
      'isNeedSign': True,
    }

    try:
      res = requests.post(url, headers=headers, json=body).json()
      if res['code'] == '000000':
        self.id_token = res['data']['idToken']
        self.user_id = res['data']['userId']
        self.refresh_token = res['data']['refreshToken']
        id_token_expires_in = res['data'].get('expireIn')

        # 解析 JWT 获取 idpId
        jwt_payload = utils.decode_jwt_payload(self.id_token)
        if jwt_payload:
          self.idp_id = jwt_payload.get('sub')

        self.log('验证码登录成功')
        self.save_cache(id_token_expires_in=id_token_expires_in)
        return True
      else:
        error_code = res.get('code', 'Unknown')
        error_msg = res.get('description') or res.get('message', '未知错误')
        self.log(f'验证码登录失败: Code=[{error_code}], Message={error_msg}')
        return False
    except Exception as e:
      self.log(f'验证码登录异常: {e}')
      return False

  # 从环境变量解析当前账号的验证码
  def _parse_sms_code_from_env(self):
    """
    从环境变量 SVW_SMS_CODES 解析当前账号的验证码

    环境变量格式：
    - 账号之间用 & 分隔
    - 账号和验证码用 # 分隔
    """
    env_value = utils.get_environ('SVW_SMS_CODES', '', False)
    if not env_value:
      return ''

    # 按账号分割
    accounts = env_value.split('&')
    for account_code in accounts:
      if not account_code:
        continue
      # 按账号和验证码分割
      parts = account_code.split('#')
      if len(parts) == 2:
        account, code = parts
        if account == self.account:
          return code

    return ''

  # 等待用户输入验证码
  def wait_for_sms_code(self, timeout_minutes=4):
    ql_flag = utils.is_ql_env()
    timeout_seconds = timeout_minutes * 60
    end_time = datetime.now() + timedelta(seconds=timeout_seconds)

    if ql_flag:
      print(f'\n[{self.account}] ========== 请将短信验证码配置环境变量[SVW_SMS_CODES]后运行 ==========')
      sms_code = self._parse_sms_code_from_env()
      if sms_code:
        print(f'\n[{self.account}] 已从环境变量获取验证码')
        return sms_code
      else:
        print(f'\n[{self.account}] 未配置环境变量[SVW_SMS_CODES], 请配置后再次运行')
        exit(0)
    else:
      print(f'\n[{self.account}] ========== 请输入短信验证码 ==========')
    print(f'[{self.account}] 超时时间: {timeout_minutes}分钟')
    print(f'[{self.account}] ========================================')

    while datetime.now() < end_time:
      remaining_seconds = int((end_time - datetime.now()).total_seconds())

      if remaining_seconds <= 0:
        break

      remaining_minutes = remaining_seconds // 60
      remaining_secs = remaining_seconds % 60

      try:
        # 本地环境：显示倒计时并等待输入
        sms_code = input(f'\r[{self.account}] 剩余时间: {remaining_minutes}分{remaining_secs:02d}秒，请输入验证码 > ').strip()
        if sms_code:
          print(f'\n[{self.account}] 已接收验证码输入')
          return sms_code

      except (EOFError, KeyboardInterrupt):
        print(f'\n[{self.account}] 检测到中断，退出验证码输入')
        return None
      except Exception:
        # 忽略其他输入异常
        pass

    print(f'\n[{self.account}] ========== 验证码输入超时 ==========')
    return None

  # 获取服务端令牌
  def get_server_token(self):
    if not self.id_token:
      self.log('缺少id_token,请先登录!')
      return False

    self.log_action('获取服务端令牌')

    url = 'https://api.mos.csvw.com/mos/security/api/v1/app/token'
    headers = self._build_app_headers()
    headers['NOT_NEED_TOKEN'] = 'NOT_NEED_TOKEN'
    body = {
      'consentTypeList': 'app_privacy,app_agreement',
      'idToken': self.id_token,
      'isNeedSign': True,
      'scope': 'openid'
    }

    try:
      res = requests.post(url, headers=headers, json=body).json()
      if res['code'] == '000000':
        self.server_token = f'{res["data"]["tokenType"]} {res["data"]["accessToken"]}'
        self.refresh_token = res['data']['refreshToken']
        self.user_id = res['data'].get('userId', self.user_id)

        server_token_expires_in = res['data'].get('expiresIn')

        self.log('获取服务端令牌成功')
        self.save_cache(server_token_expires_in=server_token_expires_in)
        return True
      else:
        self.log(f'获取服务端令牌失败: {res.get("description", "未知错误")}')
        return False
    except Exception as e:
      self.log(f'获取令牌异常: {e}')
      return False

  # 设备上报
  def upload_device(self):
    self.log_action('设备上报')

    url = 'https://api.mos.csvw.com/mos/security/api/v1/mdm/uploadDevice'
    headers = self._build_app_headers()

    # 从 did 解析设备信息
    device_info = parse_device_info_from_did(self.did)

    body = {
      'appBuild': '276',
      'appName': '上汽大众',
      'deviceId': self.device_id,
      'deviceInfo': '',
      'locallizedModel': '',
      'deviceName': 'Xiaomi',
      'systemName': 'android',
      'did': self.did,
      'appBrand': 'vw',
      'deviceBrand': 'vw',
      'terminalType': 'app',
      'model': device_info['model'],
      'systemVersion': device_info['systemVersion'],
      'appVersion': device_info['appVersion']
    }

    try:
      res = requests.post(url, headers=headers, json=body).json()
      if res['code'] == '000000':
        self.log('设备上报成功')
        return True
      else:
        self.log(f'设备上报失败: {res.get("description", "未知错误")}')
        return False
    except Exception as e:
      self.log(f'设备上报异常: {e}')
      return False

  # 设备认证
  def device_auth(self):
    if not self.server_token or not self.user_id:
      self.log('缺少server_token或user_id，无法进行设备认证')
      return False

    if not self.upload_device():
      self.log('设备上报失败，跳过设备认证')
      return False

    self.log_action('设备认证')

    url = 'https://api.mos.csvw.com/mos/security/api/v1/mdm/updateAccount'
    headers = self._build_app_headers(need_auth=True)
    body = {
      'deviceId': self.device_id,
      'did': self.did,
      'email': '',
      'phone': self.account,
      'status': 'active',
      'terminalType': 'app',
      'userBrand': 'vw',
      'userId': str(self.user_id)
    }

    try:
      res = requests.post(url, headers=headers, json=body).json()
      if res['code'] == '000000':
        self.log('设备认证成功')
        self.is_auth = True
        return True
      else:
        self.log(f'设备认证失败: {res.get("description", "未知错误")}')
        return False
    except Exception as e:
      self.log(f'设备认证异常: {e}')
      return False

  # 获取用户令牌
  def get_sx_token(self):
    if not self.server_token or not self.user_id:
      self.log('缺少server_token或user_id!')
      return False

    self.log_action('获取用户令牌')

    url = f'https://api.mos.csvw.com/mos/operation/home/api/v2/users/{self.user_id}/getSxToken'
    headers = self._build_app_headers(need_auth=True)

    try:
      res = requests.get(url, headers=headers).json()
      if res['code'] == '000000':
        self.sx_token = res['data']['userToken']
        self.log('获取用户令牌成功')
        return True
      else:
        self.log(f'获取用户令牌失败: {res.get("description", "未知错误")}')
        return False
    except Exception as e:
      self.log(f'获取用户令牌异常: {e}')
      return False

  # 刷新服务端令牌
  def refresh_server_token(self):
    if not self.refresh_token:
      self.log('缺少refresh_token，无法刷新!')
      return False

    self.log_action('刷新服务端令牌')

    url = 'https://api.mos.csvw.com/mos/security/api/v1/app/at/actions/refresh'
    headers = self._build_app_headers()
    body = {
      'refreshToken': self.refresh_token,
      'scope': 'user'
    }

    try:
      res = requests.put(url, headers=headers, json=body).json()
      if res['code'] == '000000':
        self.server_token = f'{res["data"]["tokenType"]} {res["data"]["accessToken"]}'
        self.refresh_token = res['data']['refreshToken']
        self.user_id = res['data'].get('userId', self.user_id)

        server_token_expires_in = res['data'].get('expireIn')

        self.log('刷新服务端令牌成功')
        self.save_cache(server_token_expires_in=server_token_expires_in)
        return True
      else:
        self.log(f'刷新服务端令牌失败: {res.get("description", "未知错误")}')
        return False
    except Exception as e:
      self.log(f'刷新服务端令牌异常: {e}')
      return False

  # 刷新用户令牌
  def refresh_sx_token(self):
    if not self.server_token or not self.user_id or not self.sx_token:
      self.log('缺少必要参数!')
      return False

    self.log_action('刷新用户令牌')

    url = f'https://api.mos.csvw.com/mos/operation/home/api/v2/users/{self.user_id}/refreshSxToken'
    headers = self._build_app_headers(need_auth=True, need_sx_token=True)
    body = {'oldSxToken': self.sx_token}

    try:
      res = requests.post(url, headers=headers, json=body).json()
      if res['code'] == '000000':
        self.sx_token = res['data']['userToken']
        self.log('刷新用户令牌成功')
        return True
      else:
        self.log(f'刷新用户令牌失败: {res.get("description", "未知错误")}')
        return False
    except Exception as e:
      self.log(f'刷新令牌异常: {e}')
      return False

  # 初始化token
  def init_tokens(self):
    need_sms_codes = ['510073']  # 需要验证码登录的错误码
    need_sms_keywords = ['验证码', '短信', 'sms']  # 请使用验证码登录

    def try_pwd_login():
      """尝试密码登录，失败时检查是否需要验证码登录"""
      success, error_code, error_msg = self.pwd_login()
      if success:
        return True, False  # 登录成功，不需要验证码

      # 优先检查错误码是否提示需要验证码登录
      if error_code and error_code in need_sms_codes:
        self.log(f'检测到错误码[{error_code}]，需要验证码登录，正在切换到验证码登录方式...')
        return False, True  # 登录失败，需要验证码登录

      # 检查错误信息是否提示需要验证码登录
      if error_msg and any(keyword in error_msg for keyword in need_sms_keywords):
        self.log(f'检测到关键词，需要验证码登录，正在切换到验证码登录方式...')
        return False, True  # 登录失败，需要验证码登录

      return False, False  # 登录失败，不需要验证码登录

    def try_sms_login():
      """尝试验证码登录"""
      # 0. 优先检查环境变量是否已有验证码
      env_sms_code = self._parse_sms_code_from_env()
      if env_sms_code:
        self.log('检测到环境变量已有验证码，直接登录')
        if self.sms_login(env_sms_code):
          return True
        else:
          self.log('环境变量验证码登录失败,重新获取验证码')

      # 1. 发送验证码
      if not self.get_sms_code():
        self.log('获取验证码失败，无法继续')
        return False

      # 2. 等待输入验证码（4分钟超时）
      sms_code = self.wait_for_sms_code(timeout_minutes=4)
      if not sms_code:
        self.log('未输入验证码或输入超时，登录流程终止')
        return False

      # 3. 使用验证码登录
      if self.sms_login(sms_code):
        return True
      else:
        self.log('验证码登录失败')
        return False

    # ============ 主流程开始 ============
    # 1. 尝试从缓存加载
    if self.load_cache():
      if not self.server_token:
        if self.refresh_token:
          if not self.refresh_server_token():
            # 刷新失败，尝试重新登录
            pwd_success, need_sms = try_pwd_login()
            if pwd_success:
              self.get_server_token()
            elif need_sms:
              if not try_sms_login():
                return False
              self.get_server_token()
            else:
              return False
        else:
          # 没有refresh_token，直接尝试登录
          pwd_success, need_sms = try_pwd_login()
          if pwd_success:
            self.get_server_token()
          elif need_sms:
            if not try_sms_login():
              return False
            self.get_server_token()
          else:
            return False
      # 有server_token，继续
      if self.sx_token:
        self.refresh_sx_token()
      elif self.server_token:
        self.get_sx_token()

    # 2. 无缓存，直接登录
    else:
      pwd_success, need_sms = try_pwd_login()
      if pwd_success:
        self.get_server_token()
        self.get_sx_token()
      elif need_sms:
        if not try_sms_login():
          return False
        self.get_server_token()
        self.get_sx_token()
      else:
        return False

    return bool(self.server_token)

  # ==================== 签到系统 ====================
  # 查询签到日历
  def get_sign_calendar(self):
    if not self.sx_token:
      self.log('缺少sx_token，跳过签到日历查询')
      return None
    if not self.user_id or not self.idp_id:
      self.log('缺少user_id或idp_id!')
      return None

    self.log_action('查询签到日历')

    url = 'https://mweb.mos.csvw.com/mos/operation/home/api/v1/user/sign/info'
    params = {
      'type': 'task',
      'activityId': 'MOS_SX_Sign_1001',
      'brand': 'vw',
      'userId': self.user_id,
      'idpId': self.idp_id
    }
    headers = self._build_h5_headers(
      url='https://mweb.mos.csvw.com/mos/operation/home/api/v1/user/sign/info',
      method='GET',
      need_auth=True,
      need_sx_token=True
    )

    try:
      res = requests.get(url, params=params, headers=headers).json()
      if res['code'] == '000000':
        data = res['data']
        current_status = data.get('currentSignStatus')
        sign_count = data.get('signCount')

        status_text = '已签到' if current_status else '未签到'
        self.log(f'签到日历查询成功，已连续签到{sign_count}天，今日{status_text}')

        return data
      else:
        self.log(f'签到日历查询失败: {res.get("description", "未知错误")}')
        return None
    except Exception as e:
      self.log(f'签到日历查询异常: {e}')
      return None

  # 执行签到
  def do_sign_in(self):
    if not self.sx_token:
      self.log('缺少sx_token，跳过签到')
      return False
    if not self.user_id or not self.idp_id:
      self.log('缺少user_id或idp_id!')
      return False

    self.log_action('执行签到')

    url = 'https://mweb.mos.csvw.com/mos/operation/home/api/v1/user/sign/info'
    headers = self._build_h5_headers(
      url=url,
      method='POST',
      need_auth=True,
      need_sx_token=True
    )
    body = {
      'activityId': 'MOS_SX_Sign_1001',
      'brand': 'VW',
      'idpId': self.idp_id,
      'userId': str(self.user_id)
    }

    try:
      res = requests.post(url, headers=headers, json=body)

      # 检测 WAF 响应
      if 'text/html' in res.headers.get('Content-Type', ''):
        self.log('触发WAF，正在计算cookie...')
        cookie_value = utils.calculate_acw_sc__v2(res.text)
        if cookie_value:
          headers['Cookie'] = f'acw_sc__v2={cookie_value}'
          res = requests.post(url, headers=headers, json=body)

      res_json = res.json()

      if res_json.get('code') == '000000':
        data = res_json.get('data', {})
        sign_count = data.get('signCount')
        self.log(f'签到成功，已连续签到{sign_count}天')
        return True
      else:
        error_msg = res_json.get('message', res_json.get('description', '未知错误'))
        self.log(f'签到失败: {error_msg}')
        return False
    except Exception as e:
      self.log(f'签到异常: {e}')
      return False

  # 签到流程
  def process_sign_in(self):
    calendar_data = self.get_sign_calendar()

    if calendar_data:
      current_status = calendar_data.get('currentSignStatus')
      if current_status:
        self.log(f'今日已完成签到，连续签到{calendar_data.get("signCount")}天')
      else:
        self.do_sign_in()
    else:
      self.log('签到状态查询失败')

  # ==================== 任务系统 ====================
  # 获取任务列表
  def get_task_list(self):
    if not self.sx_token:
      self.log('缺少sx_token，跳过任务列表获取')
      return None

    self.log_action('获取任务列表')

    url = 'https://mweb.mos.csvw.com/mossx/intgw/cop/ma/task/open/api/v2/userTaskShow/userTaskList'
    params = {'channel': 'TC10000000'}
    headers = self._build_h5_headers(
      url=url,
      method='GET',
      need_auth=True,
      need_sx_token=True
    )

    try:
      res = requests.get(url, params=params, headers=headers).json()
      if res.get('code') == '00':
        task_list = res.get('data', [])
        self.log(f'获取任务列表成功，共{len(task_list)}个任务')

        # 解析任务信息
        parsed_tasks = []
        for task in task_list:
          task_name = task.get('taskName', '')
          task_type = task.get('taskTypeName', '')
          completed = task.get('completeNumTotal', 0)
          upper_limit = task.get('completeNumUpperLimit', 0)
          extend_info = task.get('extendInfoMap', {})
          award_count = extend_info.get('awardCount', 0)

          parsed_tasks.append({
            'name': task_name,
            'type': task_type,
            'completed': completed,
            'upper_limit': upper_limit,
            'award_count': award_count,
            'raw': task
          })

        return parsed_tasks
      else:
        self.log(f'获取任务列表失败: {res.get("message", "未知错误")}')
        return None
    except Exception as e:
      self.log(f'获取任务列表异常: {e}')
      return None

  # 输出任务概要
  def print_task_summary(self, tasks):
    if not tasks:
      return

    self.log_action('输出任务概要')

    for task in tasks:
      task_name = task['name']
      task_type = task['type']
      completed = task['completed']
      upper_limit = task['upper_limit']
      award_count = task['award_count']

      in_whitelist = (not self.task_whitelist) or (task_name in self.task_whitelist)
      task_info = f'{task_type}-{task_name}-进度[{completed}/{upper_limit}]-{award_count}积分/次'

      if not in_whitelist:
        task_info += '-已跳过'

      self.log(task_info, show_prefix=False)

  # 获取最大任务次数
  def get_max_task_limit(self, tasks):
    if not tasks:
      return 0  # 默认值

    max_limit = 1
    for task in tasks:
      limit = task['upper_limit']
      if limit > max_limit:
        max_limit = limit

    return max_limit

  # 过滤白名单任务
  def filter_whitelist_tasks(self, tasks):
    if not self.task_whitelist:
      return tasks

    return [t for t in tasks if t['name'] in self.task_whitelist]

  # ==================== 文章互动 ====================
  # 获取文章列表
  def get_article_list(self, page_index=1, page_size=20):
    if not self.server_token or not self.sx_token or not self.user_id or not self.idp_id:
      self.log('缺少必要参数!')
      return None

    self.log_action('获取文章列表')

    url = 'https://api.mos.csvw.com/mos/operation/home/api/v2/app/brand/homePage/getArticleAndVideoDataPage'
    headers = self._build_app_headers(need_auth=True, need_sx_token=True)
    body = {
      'brand': 'vw',
      'categoryType': 'activity,recommend,drive,homeCard,sxTaskWarn,sxContentCollection,sxRecommendFriend,sxHotTopic,sxHotWindow,sxNearbyActivity,sxMallGoods,sxNearbyCarClub,sxDrive',
      'channel': 'app',
      'idpId': self.idp_id,
      'pageIndex': page_index,
      'pageSize': page_size,
      'size': 0,
      'sxToken': self.sx_token,
      'terminalType': 'android',
      'userId': str(self.user_id)
    }

    try:
      res = requests.post(url, headers=headers, json=body).json()
      if res['code'] == '000000':
        page_data = res.get('data', {}).get('pageData', [])
        total_count = res.get('data', {}).get('totalCount', 0)
        self.log(f'获取文章列表成功，共{total_count}篇，本页{len(page_data)}篇')

        # 解析文章信息
        articles = []
        for item in page_data:
          data_vo = item.get('dataVO', {})
          article = {
            'id': data_vo.get('ugcId'),
            'title': data_vo.get('title', ''),
            'isThumb': data_vo.get('isThumb'),
            'thumbNum': data_vo.get('thumbNum', 0),
            'commentNum': data_vo.get('commentNum', 0),
            'browseNum': data_vo.get('browseNum', 0),
            'contentType': data_vo.get('contentType')
          }
          articles.append(article)

        return articles
      else:
        self.log(f'获取文章列表失败: {res.get("description", "未知错误")}')
        return None
    except Exception as e:
      self.log(f'获取文章列表异常: {e}')
      return None

  # 挑选未点赞文章
  def select_unliked_articles(self, articles, limit):
    if not articles:
      return []

    # 过滤出未点赞的文章（isThumb != 1）
    unliked = [a for a in articles if a.get('isThumb') != 1]
    # 按数量限制
    selected = unliked[:limit] if limit > 0 else unliked

    self.log(f'挑选{len(selected)}篇未点赞文章（共{len(unliked)}篇未点赞）')

    return selected

  # 文章点赞
  def do_like(self, article_id):
    if not self.server_token or not self.user_id:
      self.log('缺少必要参数!')
      return False

    url = 'https://api.mos.csvw.com/cms/home/community/dynamic/like'
    headers = self._build_app_headers(need_auth=True, need_sx_token=True)
    body = {
      'targetId': article_id,
      'likeOrNot': '1',
      'targetType': '0',
      'userId': str(self.user_id)
    }

    try:
      res = requests.put(url, headers=headers, json=body).json()
      if res.get('code') == 200:
        like_qty = res.get('data', {}).get('likeQty', '0')
        self.log(f'文章点赞成功，当前点赞数: {like_qty}', show_prefix=False)
        return True
      else:
        self.log(f'文章点赞失败: {res.get("message", "未知错误")}', show_prefix=False)
        return False
    except Exception as e:
      self.log(f'文章点赞异常: {e}', show_prefix=False)
      return False

  # 文章浏览
  def do_read_article(self, article_id):
    if not self.sx_token:
      return False

    # 检查是否已执行过阅读
    if self.article_read_done:
      return True

    url = 'https://m.svw-volkswagen.com/community-api/article/read'
    body = {'id': article_id}

    headers = self._build_h5_headers(
      url=url,
      method='PUT',
      need_sign=True,
      need_sx_token=True,
      referer=f'https://m.svw-volkswagen.com/community/article/article-detail?id={article_id}&viewType=1'
    )

    try:
      res = requests.put(url, headers=headers, json=body).json()
      if res.get('code') == 200:
        self.log('文章浏览成功（今日已完成）', show_prefix=False)
        self.article_read_done = True
        return True
      else:
        self.log(f'文章浏览失败: {res.get("message", "未知错误")}', show_prefix=False)
        return False
    except Exception as e:
      self.log(f'文章浏览异常: {e}', show_prefix=False)
      return False

  # 文章分享
  def do_share_article(self, article_id):
    if not self.sx_token:
      return False

    url = 'https://m.svw-volkswagen.com/community-api/article/share-event'
    body = {
      'shareId': article_id,
      'sharingType': 1
    }

    headers = self._build_h5_headers(
      url=url,
      method='POST',
      need_sign=True,
      need_sx_token=True,
      referer=f'https://m.svw-volkswagen.com/community/article/article-detail?id={article_id}&viewType=1'
    )

    try:
      resp = requests.post(url, headers=headers, json=body)
      if resp.status_code == 200:
        self.log(f'文章分享成功', show_prefix=False)
        return True
      else:
        self.log(f'文章分享失败: {resp.status_code}', show_prefix=False)
        return False
    except Exception as e:
      self.log(f'文章分享异常: {e}', show_prefix=False)
      return False

  # 获取评论列表
  def get_comments(self, article_id, page=0, size=10):
    if not self.sx_token:
      return None

    url = 'https://m.svw-volkswagen.com/community-api/comment/art-comment-list'
    params = {
      'artId': article_id,
      'page': page,
      'size': size
    }

    headers = self._build_h5_headers(
      url=url,
      method='GET',
      need_sign=True,
      need_sx_token=True,
      referer=f'https://m.svw-volkswagen.com/community/article/article-detail?id={article_id}&viewType=1'
    )

    try:
      res = requests.get(url, params=params, headers=headers).json()
      if res.get('code') == 200:
        return res.get('rows', [])
      else:
        return None
    except Exception:
      return None

  # 发表评论
  def do_comment(self, article_id, content, parent_comm_id=None):
    if not self.sx_token:
      return False

    url = 'https://m.svw-volkswagen.com/community-api/comment/save'

    # 构建评论内容（HTML格式）
    comm_content_html = f'<p>{content}</p>'
    body = {
      'commPictureUrl': '',
      'replyLimit': 1,
      'artId': article_id,
      'contentCategory': 1,
      'parentCommId': parent_comm_id or '',
      'saveOrReply': 1,
      'commContent': comm_content_html,
      'mentions': [],
      'commContentWords': len(content)
    }

    headers = self._build_h5_headers(
      url=url,
      method='POST',
      need_sign=True,
      need_sx_token=True,
      referer=f'https://m.svw-volkswagen.com/community/article/article-detail?id={article_id}&viewType=1'
    )

    try:
      res = requests.post(url, headers=headers, json=body).json()
      if res.get('code') == 200:
        self.log(f'发表评论成功: {content[:20]}...', show_prefix=False)
        return True
      else:
        self.log(f'发表评论失败: {res.get("message", "未知错误")}', show_prefix=False)
        return False
    except Exception as e:
      self.log(f'发表评论异常: {e}', show_prefix=False)
      return False

  # 处理文章互动
  def process_article_interactions(self, articles):
    if not articles:
      self.log('没有可操作的文章')
      return

    # 获取任务列表以确定操作次数
    tasks = self.get_task_list()
    if not tasks:
      self.log('无法获取任务列表，跳过文章互动')
      return

    # 过滤白名单任务
    whitelist_tasks = self.filter_whitelist_tasks(tasks)

    # 解析任务次数
    like_limit = 0
    share_limit = 0
    comment_limit = 0

    for task in whitelist_tasks:
      task_name = task['name']
      upper_limit = task['upper_limit']
      completed = task['completed']

      if '点赞' in task_name or '喜欢' in task_name:
        like_limit = max(like_limit, upper_limit - completed)
      elif '分享' in task_name:
        share_limit = max(share_limit, upper_limit - completed)
      elif '评论' in task_name or '互动' in task_name:
        comment_limit = max(comment_limit, upper_limit - completed)

    # 如果没有需要执行的任务，直接返回
    if like_limit == 0 and share_limit == 0 and comment_limit == 0:
      self.log('所有互动任务已完成')
      return

    self.log_action('开始文章互动')

    # 限制文章数量
    article_count = min(len(articles), max(like_limit, share_limit, comment_limit))
    selected_articles = articles[:article_count]

    # 执行点赞
    if like_limit > 0:
      self.log(f'执行文章点赞（目标{like_limit}次）', show_prefix=False)
      for i, article in enumerate(selected_articles[:like_limit]):
        self.do_like(article['id'])

    # 执行阅读
    if selected_articles:
      self.do_read_article(selected_articles[0]['id'])

    # 执行分享
    if share_limit > 0:
      self.log(f'执行文章分享（目标{share_limit}次）', show_prefix=False)
      for i, article in enumerate(selected_articles[:share_limit]):
        self.do_share_article(article['id'])

    # 执行评论（随机复制子评论）
    if comment_limit > 0:
      self.log(f'执行文章评论（目标{comment_limit}次）', show_prefix=False)
      comment_count = 0

      for article in selected_articles:
        if comment_count >= comment_limit:
          break

        # 获取评论列表
        comments = self.get_comments(article['id'], size=20)

        if comments:
          # 随机选择一条评论
          random_comment = random.choice(comments)
          comment_content = utils.strip_html_tags(random_comment.get('commContent', ''))
          parent_id = random_comment.get('id')

          # 复制评论内容并回复评论
          if comment_content and parent_id:
            if self.do_comment(article['id'], comment_content, parent_comm_id=parent_id):
              comment_count += 1

  # ==================== 占位方法 ====================
  # 抽奖
  def lottery(self):
    pass

  # 添加tingyun请求头
  def add_tingyun_header(self, url, method, data=None, params=None):
    return {}

  # 构建APP请求头
  def _build_app_headers(self, need_auth=False, need_sx_token=False):
    headers = {
      'User-Agent': self.app_config.get('user_agent', 'okhttp/4.12.0'),
      'Content-Type': 'application/json',
      'Did': self.did,
      'Timestamp': utils.create_timestamp(13),
      'deviceId': self.device_id,
      'OS': 'Android',
      'Nonce': utils.create_uuid(),
      'Authorization': self.server_token if need_auth else ''
    }
    if need_sx_token and self.sx_token:
      headers['X-COP-accessToken'] = self.sx_token
    # 调用 add_tingyun_header 补充 tingyun 请求头
    tingyun_headers = self.add_tingyun_header('', 'POST')
    headers.update(tingyun_headers)
    return headers

  # 构建H5请求头
  def _build_h5_headers(self, url=None, method='GET', need_sign=False, need_sx_token=False, need_auth=False,
                        referer=None):
    headers = {
      'User-Agent': self.h5_config.get('user_agent',
                                       'Mozilla/5.0 (Linux; Android 16; 23127PN0CC Build/BP2A.250605.031.A3; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/142.0.7444.174 Mobile Safari/537.36 SVW Android'),
      'Content-Type': 'application/json',
      'Timestamp': utils.create_timestamp(13),
      'deviceId': self.device_id,
      'Did': self.did,
      'Referer': referer or self.h5_config.get('referer', 'https://mweb.mos.csvw.com/mos-mweb/app-misc/')
    }
    if need_auth and self.server_token:
      headers['Authorization'] = self.server_token
    if need_sx_token and self.sx_token:
      headers['X-COP-accessToken'] = self.sx_token
    if need_sign and url:
      app_key = self.h5_config.get('app_key', 'SVW_COMMUNITY_H5')
      sign_data = generate_x_sign(url, method, sx_token=self.sx_token if need_sx_token else None, app_key=app_key)
      headers.update(sign_data)
    # 调用 add_tingyun_header 补充 tingyun 请求头
    tingyun_headers = self.add_tingyun_header(headers.get('Referer', ''), 'GET')
    headers.update(tingyun_headers)
    return headers

  # ==================== 主流程 ====================
  def main(self):
    self.msg = []  # 清空消息列表
    self.log(f'========== 账号[{self.account}]开始执行 ==========', show_prefix=False)

    # 1. 初始化 Token
    if not self.init_tokens():
      self.log('Token初始化失败！')
      self.flush_messages()
      return
    # 1.1 设备认证绑定
    if not self.is_auth:
      self.log('检测到设备未认证，尝试设备认证')
      self.device_auth()
    # 1.2 保存缓存
    self.save_cache()

    # 2. 签到
    self.process_sign_in()

    # 3. 获取任务列表
    tasks = self.get_task_list()
    if tasks:
      self.print_task_summary(tasks)

      # 4. 获取文章列表并执行任务
      unliked_articles = []
      max_limit = self.get_max_task_limit(self.filter_whitelist_tasks(tasks))

      for _idx in range(10):
        articles = self.get_article_list(_idx + 1, max_limit)
        if articles:
          unliked_articles.extend(self.select_unliked_articles(articles, max_limit))
          if len(unliked_articles) >= max_limit:
            break
      self.process_article_interactions(unliked_articles)
    else:
      self.log('无法获取任务列表，跳过文章互动')

    self.log(f'========== 账号[{self.account}]执行完成 ==========', show_prefix=False)
    self.flush_messages()

  # 统一输出消息
  def flush_messages(self):
    if self.unified_msg and self.msg:
      print('\n'.join(self.msg))


# ==================== 线程执行函数 ====================
def run_threading(account, password, did, device_id, web_id=None, task_whitelist=None, unified_msg=True, h5_config=None,
                  app_config=None):
  SVW(account, password, did, device_id, web_id, task_whitelist, unified_msg, h5_config, app_config).main()


# ==================== 主程序入口 ====================
if __name__ == '__main__':
  # 初始化全局缓存
  init_global_cache()

  thread_list = []
  config = utils.read_yaml('svw_config.yml')

  print(f'当前配置版本: {config.get("version")}')
  title = config.get('title')
  task_whitelist = config.get('task_whitelist', [])
  unified_msg = config.get('unified_msg', True)

  # H5 和 APP 配置
  h5_config = config.get('h5', {})
  app_config = config.get('app', {})

  user_list = config.get('accounts')
  for user in user_list:
    thread = threading.Thread(
      target=run_threading,
      kwargs={
        'account': user['account'],
        'password': user['password'],
        'did': user.get('did'),
        'device_id': user.get('deviceId'),
        'web_id': user.get('webId'),
        'task_whitelist': task_whitelist,
        'unified_msg': unified_msg,
        'h5_config': h5_config,
        'app_config': app_config
      }
    )
    thread_list.append(thread)

  for thread in thread_list:
    thread.start()
    thread.join()

  # 所有线程结束后，统一刷新全局缓存到文件
  flush_global_cache()
