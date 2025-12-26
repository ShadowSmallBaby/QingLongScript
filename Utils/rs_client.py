import re
import execjs
from curl_cffi import requests
from bs4 import BeautifulSoup
import utils

js_code_template = 'ZGVsZXRlIF9fZmlsZW5hbWU7ZGVsZXRlIF9fZGlybmFtZTtBY3RpdmVYT2JqZWN0PXVuZGVmaW5lZDt3aW5kb3c9Z2xvYmFsO2NvbnRlbnQ9J2NvbnRlbnRfY29kZSc7bmF2aWdhdG9yPXsncGxhdGZvcm0nOidMaW51eCBhYXJjaDY0J307bmF2aWdhdG9yPXsndXNlckFnZW50JzonQ3RDbGllbnQ7MTEuMC4wO0FuZHJvaWQ7MTM7MjIwODEyMTJDO05USXlNVGN3ISMhTVRVek56WSd9O2xvY2F0aW9uPXsnaHJlZic6J2h0dHBzOi8vJywnb3JpZ2luJzonJywncHJvdG9jb2wnOicnLCdob3N0JzonJywnaG9zdG5hbWUnOicnLCdwb3J0JzonJywncGF0aG5hbWUnOicnLCdzZWFyY2gnOicnLCdoYXNoJzonJ307aT17bGVuZ3RoOjB9O2Jhc2U9e2xlbmd0aDowfTtkaXY9e2dldEVsZW1lbnRzQnlUYWdOYW1lOmZ1bmN0aW9uKHJlcyl7Y29uc29sZS5sb2coJ2RpduS4reeahGdldEVsZW1lbnRzQnlUYWdOYW1l77yaJyxyZXMpO2lmKHJlcz09PSdpJyl7cmV0dXJuIGl9cmV0dXJuJzxkaXY+PC9kaXY+J319O3NjcmlwdD17fTttZXRhPVt7Y2hhcnNldDonVVRGLTgnfSx7Y29udGVudDpjb250ZW50LGdldEF0dHJpYnV0ZTpmdW5jdGlvbihyZXMpe2NvbnNvbGUubG9nKCdtZXRh5Lit55qEZ2V0QXR0cmlidXRl77yaJyxyZXMpO2lmKHJlcz09PSdyJyl7cmV0dXJuJ20nfX0scGFyZW50Tm9kZTp7cmVtb3ZlQ2hpbGQ6ZnVuY3Rpb24ocmVzKXtjb25zb2xlLmxvZygnbWV0YeS4reeahHJlbW92ZUNoaWxk77yaJyxyZXMpO3JldHVybiBjb250ZW50fX19XTtmb3JtPSc8Zm9ybT48L2Zvcm0+Jzt3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcj1mdW5jdGlvbihyZXMpe2NvbnNvbGUubG9nKCd3aW5kb3fkuK3nmoRhZGRFdmVudExpc3RlbmVyOicscmVzKX07ZG9jdW1lbnQ9e2NyZWF0ZUVsZW1lbnQ6ZnVuY3Rpb24ocmVzKXtjb25zb2xlLmxvZygnZG9jdW1lbnTkuK3nmoRjcmVhdGVFbGVtZW5077yaJyxyZXMpO2lmKHJlcz09PSdkaXYnKXtyZXR1cm4gZGl2fWVsc2UgaWYocmVzPT09J2Zvcm0nKXtyZXR1cm4gZm9ybX1lbHNle3JldHVybiByZXN9fSxhZGRFdmVudExpc3RlbmVyOmZ1bmN0aW9uKHJlcyl7Y29uc29sZS5sb2coJ2RvY3VtZW505Lit55qEYWRkRXZlbnRMaXN0ZW5lcjonLHJlcyl9LGFwcGVuZENoaWxkOmZ1bmN0aW9uKHJlcyl7Y29uc29sZS5sb2coJ2RvY3VtZW505Lit55qEYXBwZW5kQ2hpbGTvvJonLHJlcyk7cmV0dXJuIHJlc30scmVtb3ZlQ2hpbGQ6ZnVuY3Rpb24ocmVzKXtjb25zb2xlLmxvZygnZG9jdW1lbnTkuK3nmoRyZW1vdmVDaGlsZO+8micscmVzKX0sZ2V0RWxlbWVudHNCeVRhZ05hbWU6ZnVuY3Rpb24ocmVzKXtjb25zb2xlLmxvZygnZG9jdW1lbnTkuK3nmoRnZXRFbGVtZW50c0J5VGFnTmFtZe+8micscmVzKTtpZihyZXM9PT0nc2NyaXB0Jyl7cmV0dXJuIHNjcmlwdH1pZihyZXM9PT0nbWV0YScpe3JldHVybiBtZXRhfWlmKHJlcz09PSdiYXNlJyl7cmV0dXJuIGJhc2V9fSxnZXRFbGVtZW50QnlJZDpmdW5jdGlvbihyZXMpe2NvbnNvbGUubG9nKCdkb2N1bWVudOS4reeahGdldEVsZW1lbnRCeUlk77yaJyxyZXMpO2lmKHJlcz09PSdyb290LWhhbW1lcmhlYWQtc2hhZG93LXVpJyl7cmV0dXJuIG51bGx9fX07c2V0SW50ZXJ2YWw9ZnVuY3Rpb24oKXt9O3NldFRpbWVvdXQ9ZnVuY3Rpb24oKXt9O3dpbmRvdy50b3A9d2luZG93Oyd0c19jb2RlJztmdW5jdGlvbiBtYWluKCl7Y29va2llPWRvY3VtZW50LmNvb2tpZS5zcGxpdCgnOycpWzBdO3JldHVybiBjb29raWV9'


class RS:
  def __init__(self, url, ss=requests.session.Session()):
    self.url = url
    self.ss = ss
    self.cookies = {}
    self.js_ctx = execjs.compile('')

  def statis_create(self):
    response = self.ss.get(self.url)
    res = response.text
    return self.statis_create_by_res(res)

  def post_statis_create(self):
    response = self.ss.post(self.url, verify=False)
    res = response.text
    return self.statis_create_by_res(res)

  def statis_create_by_res(self, res):
    soup = BeautifulSoup(res, 'html.parser')
    scripts = soup.find_all('script')
    rs_url = ts_code = ''
    for script in scripts:
      if 'src' in str(script):
        rs_url = re.findall('src="([^"]+)"', str(script))[0]
      if '$_ts=window' in script.get_text():
        ts_code = script.get_text()
    urls = self.url.split('/')
    rs_url = urls[0] + '//' + urls[2] + rs_url
    # print(f'瑞数脚本地址: {rs_url}')
    ts_code += self.ss.get(rs_url).text
    content_code = soup.find_all('meta')[1].get('content')
    js_code = utils.base64_decode(js_code_template).replace('content_code', content_code).replace("'ts_code'", ts_code)
    self.js_ctx = execjs.compile(js_code)
    for key in self.ss.cookies:
      self.cookies[key] = self.ss.cookies[key]
    return self

  def dynamic_create(self):
    bd = self.dynamic_create_only()
    self.cookies[bd[0]] = bd[1]
    return self

  def dynamic_create_only(self):
    return self.js_ctx.call('main').split('=')

  def reset_cookies(self, ck):
    bd = self.dynamic_create_only()
    ck[bd[0]] = bd[1]
    return self

  def get_cookie_str(self):
    return utils.dict_to_str(self.cookies, sep=';')

  def build(self):
    return self.statis_create().dynamic_create()

  def post_build(self):
    return self.post_statis_create().dynamic_create()


if __name__ == '__main__':
  rs = RS('https://wapact.189.cn:9001/gateway/standExchange/detailNew/exchange').post_build()
  print(rs.get_cookie_str())
