import requests
import execjs


with open('rev_api.js',mode='r',encoding='utf-8') as f:
    js_code  = f.read()
    ctx = execjs.compile(js_code)
    p,date =  ctx.call('login')
    print(p)
    print(date)


headers = {
    "accept": "application/json, text/javascript, */*; q=0.01",
    "accept-language": "zh-CN,zh;q=0.9",
    "authorization": p,
    "cache-control": "no-cache",
    "origin": "https://hust.pages.dev",
    "pragma": "no-cache",
    "priority": "u=1, i",
    "referer": "https://hust.pages.dev/",
    "sec-ch-ua": "\"Chromium\";v=\"128\", \"Not;A=Brand\";v=\"24\", \"Google Chrome\";v=\"128\"",
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "\"Windows\"",
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "cross-site",
    "source": "s",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "x-date": date
}

def get(teacher='王伟',lesson=''):
    url = "https://service-983keaku-1300473173.gz.apigw.tencentcs.com/s"
    params = {
        "teacher": teacher,
        "lesson":lesson,
        "number": "",
        "year": "",
        "searchtype": "1",
        "exact": "undefined",
        "pageSize": "20",
        "pageNum": "1",
        "t": "AzW_uhujkA" #  写死?
    }
    response = requests.get(url, headers=headers, params=params)
    res = response.json()
    return [i for i in  res['score']]

if __name__ == '__main__':
    print(get())