# 工具帮助文档

Dirsearch

```
# 强制参数
-u URL, --url=URL            目标URL，可以使用多个标志。
-l PATH, --url-file=PATH     URL列表文件。
--stdin                      从标准输入读取URL。
--cidr=CIDR                  目标CIDR。
--raw=PATH                   从文件加载原始HTTP请求（使用--scheme标志设置协议）。
-s SESSION_FILE, --session=SESSION_FILE  会话文件。
--config=PATH                配置文件的完整路径，默认为config.ini。

# 字典设置
-w WORDLISTS, --wordlists=WORDLISTS       自定义字典列表（以逗号分隔）。
-e EXTENSIONS, --extensions=EXTENSIONS    以逗号分隔的扩展名列表（例如，php，asp）。
-f, --force-extensions        将扩展名添加到每个字典条目的末尾。
-O, --overwrite-extensions    用指定的扩展名（通过-e选择）覆盖字典中的其他扩展名。
--exclude-extensions=EXTENSIONS         以逗号分隔的要排除的扩展名列表（例如，asp，jsp）。
--remove-extensions           删除所有路径中的扩展名（例如，admin.php -> admin）。
--prefixes=PREFIXES           将自定义前缀添加到所有字典条目中（以逗号分隔）。
--suffixes=SUFFIXES           将自定义后缀添加到所有字典条目中，忽略目录（以逗号分隔）。
-U, --uppercase               字典转为大写。
-L, --lowercase               字典转为小写。
-C, --capital                 字典首字母大写。

# 通用设置
-t THREADS, --threads=THREADS  线程数。
-r, --recursive               递归进行暴力破解。
--deep-recursive              对每个目录深度执行递归扫描（例如，api/users -> api/）。
--force-recursive              对每个找到的路径进行递归暴力破解，而不仅仅是目录。
-R DEPTH, --max-recursion-depth=DEPTH  最大递归深度。
--recursion-status=CODES      执行递归扫描所需的有效状态码，支持范围（以逗号分隔）。
--subdirs=SUBDIRS             扫描给定URL的子目录（以逗号分隔）。
--exclude-subdirs=SUBDIRS      在递归扫描期间排除以下子目录（以逗号分隔）。
-i CODES, --include-status=CODES  包含的状态码，以逗号分隔，支持范围（例如，200，300-399）。
-x CODES, --exclude-status=CODES  排除的状态码，以逗号分隔，支持范围（例如，301，500-599）。
--exclude-sizes=SIZES          以逗号分隔的按大小排除的响应（例如，0B，4KB）。
--exclude-text=TEXTS           可以使用多个标志按文本排除响应。
--exclude-regex=REGEX          通过正则表达式排除响应。
--exclude-redirect=STRING      如果匹配重定向URL的正则表达式（或文本），则排除响应（例如，'/index.html'）。
--exclude-response=PATH        类似于指定页面的响应的响应排除，路径作为输入（例如，404.html）。
--skip-on-status=CODES         每当命中这些状态码之一时跳过目标，以逗号分隔，支持范围。
--min-response-size=LENGTH      最小响应长度。
--max-response-size=LENGTH      最大响应长度。
--max-time=SECONDS             扫描的最大运行时间。
--exit-on-error                发生错误时退出。

# 请求设置
-m METHOD, --http-method=METHOD  HTTP方法（默认：GET）。
-d DATA, --data=DATA            HTTP请求数据。
--data-file=PATH                包含HTTP请求数据的文件。
-H HEADERS, --header=HEADERS     HTTP请求头，可以使用多个标志。
--header-file=PATH              包含HTTP请求头的文件。
-F, --follow-redirects          跟随HTTP重定向。
--random-agent                  为每个请求选择随机User-Agent。
--auth=CREDENTIAL               身份验证凭据（例如，user:password或bearer token）。
--auth-type=TYPE                身份验证类型（basic，digest，bearer，ntlm，jwt，oauth2）。
--cert-file=PATH                包含客户端证书的文件。
--key-file=PATH                 包含客户端证书私钥的文件（未加密）。
--user-agent=USER_AGENT.
--cookie=COOKIE.

# 连接设置
--timeout=TIMEOUT                连接超时。
--delay=DELAY                    请求之间的延迟。
--proxy=PROXY                    代理URL（HTTP/SOCKS），可以使用多个标志。
--proxy-file=PATH                包含代理服务器的文件。
--proxy-auth=CREDENTIAL          代理身份验证凭据。
--replay-proxy=PROXY             用找到的路径重新播放的代理。
--tor                            使用Tor网络作为代理。
--scheme=SCHEME                  原始请求的协议或URL中没有协议时的协议（默认：自动检测）。
--max-rate=RATE                  每秒的最大请求数。
--retries=RETRIES                失败请求的重试次数。
--ip=IP                          服务器IP地址。

# 高级设置
--crawl                          在响应中爬取新路径。

# 视图设置
--full-url                       在输出中显示完整的URL（在安静模式下自动启用）。
--redirects-history              显示重定向历史。
--no-color                       无彩色输出。
-q, --quiet-mode                 安静模式。

# 输出设置
-o PATH, --output=PATH           输出文件
```

Gobuster

```
用法：
  gobuster dir [flags]

参数：
  -a, --useragent string         设置User-Agent字符串（默认为 "gobuster/3.0.1"）
  -b, --statuscodesblacklist string   负状态码（如果设置，将覆盖statuscodes）
  -c, --cookies string                用于请求的Cookies
  -e, --expanded                      扩展模式，打印完整的URL
  -f, --addslash                      对每个请求追加 /
  -h, --help                          显示帮助信息
  -H, --headers stringArray           指定HTTP头部，-H 'Header1: val1' -H 'Header2: val2'
  -k, --insecuressl                   跳过SSL证书验证
  -l, --includelength                 在输出中包含响应体的长度
  -n, --nostatus                      不打印状态码
  -o, --output string                 输出结果的文件（默认为stdout）
  -p, --proxy string                  用于请求的代理 [http(s)://host:port]
  -P, --password string               基本身份验证的密码
  -r, --followredirect                跟随重定向
  -s, --statuscodes string            正状态码（默认为 "200,204,301,302,307,401,403"）
  -t, --threads int                   并发线程数（默认为10）
  -u, --url string                    目标URL
  -U, --username string               基本身份验证的用户名
  -v, --verbose                       详细输出（错误）
  -w, --wordlist string               字典文件的路径
  -x, --extensions string             要搜索的文件扩展名
  --timeout duration                  HTTP超时（默认为10秒）
  --wildcard                          当发现通配符时强制继续操作
  -z, --noprogress                    不显示进度

全局参数：
  -q, --quiet                         不打印横幅和其他噪音
```

curl

```
# 基本用法
curl [options...] <url>

# 连接选项
--abstract-unix-socket <path>          使用抽象的Unix域套接字连接
--alt-svc <file name>                  启用带有此缓存文件的alt-svc
--anyauth                              选择任意身份验证方法
-E, --cert <certificate[:password]>   客户端证书文件和密码
--cert-status                          验证服务器证书的状态通过OCSP-staple
--cert-type <type>                     证书类型（DER/PEM/ENG/P12）
--ciphers <list of ciphers>            要使用的SSL密码
--compressed                           请求压缩的响应
--compressed-ssh                       启用SSH压缩
-K, --config <file>                    从文件中读取配置
--connect-timeout <fractional seconds> 允许的最长连接时间
--connect-to <HOST1:PORT1:HOST2:PORT2>  连接到主机

# 上传选项
-a, --append                           上传时追加到目标文件
-d, --data <data>                      HTTP POST数据
--data-ascii <data>                    HTTP POST ASCII数据
--data-binary <data>                   HTTP POST二进制数据
--data-raw <data>                      HTTP POST数据，'@'允许
--data-urlencode <data>                HTTP POST数据进行URL编码

# 身份验证选项
--aws-sigv4 <provider1[:provider2[:region[:service]]]>  使用AWS V4签名身份验证
--basic                                使用HTTP基本身份验证
--digest                               使用HTTP摘要身份验证
--ntlm                                 使用HTTP NTLM身份验证
--ntlm-wb                              使用HTTP NTLM身份验证与winbind
--oauth2-bearer <token>                OAuth 2 Bearer Token

# 输出选项
-o, --output <file>                    写入文件而不是stdout
--output-dir <dir>                     保存文件的目录

# 代理选项
-x, --proxy [protocol://]host[:port]    使用此代理
--proxy-anyauth                        选择任意代理身份验证方法
--proxy-basic                          在代理上使用基本身份验证
--proxy-ssl-ccc                        在身份验证后发送CCC
-P, --ftp-port <address>               使用PORT而不是PASV
--proxy1.0 <host[:port]>               使用给定端口上的HTTP/1.0代理
--proxytunnel                          通过HTTP代理隧道运行

# 其他选项
-H, --header <header/@file>            将自定义头传递到服务器
-i, --include                          在输出中包含协议响应头
-k, --insecure                         允许不安全的服务器连接
-L, --location                         跟随重定向
--max-redirs <num>                     允许的最大重定向次数
--retry <num>                          如果发生暂时性问题，则重试请求
-s, --silent                           静默模式，不输出信息
-v, --verbose                          使操作更具描述性
-X                                     用于指定 HTTP 请求的方法。
```
