# OCR图标验证码识别

Burp插件：[captcha-killer-modified](https://github.com/f0ng/captcha-killer-modified)

<figure><img src="../.gitbook/assets/image (110).png" alt=""><figcaption></figcaption></figure>

再将源码包下载下来，需要用到[codereg.py](https://github.com/f0ng/captcha-killer-modified/blob/main/codereg.py) 这个启动器

<figure><img src="../.gitbook/assets/image (111).png" alt=""><figcaption></figcaption></figure>

pip安装

```
pip install ddddocr 
pip install aiohttp
```

将captcha-killer-modified插件添加到burp中，再将下面的请求添加到 request template中

```
POST /reg HTTP/1.1
Host: 127.0.0.1:8888
Authorization:Basic f0ngauth
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:97.0) Gecko/20100101 Firefox/97.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 8332

<@BASE64><@IMG_RAW></@IMG_RAW></@BASE64>
```

