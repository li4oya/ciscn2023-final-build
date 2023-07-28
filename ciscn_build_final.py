import logging
from bs4 import BeautifulSoup
from scapy.all import *
# from scapy.layers.inet import IP, TCP
from multiprocessing.dummy import Pool as ThreadPool
# from tqdm import tqdm
import threading
import json
import re
import requests
import platform
from ftplib import FTP
import paramiko
import pymysql
import telnetlib
import nmap
import redis
import os

# 设置日志级别为ERROR以避免显示过多信息
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# 全局变量，存储开放的端口
lock = threading.Lock()  # 线程锁
num_threads = 100  # 设置线程数量，根据需求进行调整

# 常用端口，加快扫描速度
scan_ports_from_file = []
with open('ports.txt', 'r') as f:
    f_ports = f.readlines()
    for each in f_ports:
        scan_ports_from_file.append(int(each.strip("\n")))


# -------------------------------------------------------------------------------------------------------------------------
# 1 探测存活主机
# 执行ping命令并返回结果
def ping(ip, ip_alive, sc):

    # 根据操作系统选择探测命令
    system_operate = getsystem()
    # Windows
    if system_operate == "Windows":
        pings=subprocess.Popen('ping -n 2 %s' % ip , shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='gbk') #这时windows，linux为ping -c 2
        result=pings.stdout.read()

    # Linux
    if system_operate == "Linux":
        pings=subprocess.Popen('ping -c 2 %s' % ip , shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8') #这时windows，linux为ping -c 2
        result, _ = pings.communicate()

    if 'ms' in result:    # 正确的结果里面有ms 就是时间的单位
        # print(ip,'open')
        ip_alive[ip] = "1"

# 多线程探测主机是否存活，用的ping探测，如遇到🈲ping主机无法
# 返回ip 与 是否存活 的字典
def scan_alive_ip(ip):
    ip_alive = {}   # 记录一个网段主机是否存活
    threads_ip = []    # 为了存线程
    semaphore=threading.Semaphore(20)   # 最多允许同时执行的线程数
    for i in range(1,256):
        t=threading.Thread(target=ping, args=(ip+str(i), ip_alive, semaphore))
        t.start()
        threads_ip.append(t)

    for t in threads_ip:    # 等所有进程结束后
        t.join()
    
    print(ip_alive)      # 输出这个网段存活主机的结果，格式为{ip:1/0} 后续将1/0改为具体端口和服务
    # print(len(ip_alive.keys()))
    return ip_alive      # ip_alive json数据格式例：{'16.163.13.23':1,...}

# 由于跨平台，每次换平台添注释删注释麻烦
def getsystem():
    # 获取当前操作系统的名称
    system = platform.system()

    return system

# -------------------------------------------------------------------------------------------------------------------------
# 2 探测端口是否开放
# 对一个端口进行一次syn扫描
# 输入一个ip与一个端口
def scan_ports(target_ip):
    # 创建线程并执行端口扫描
    threads = []
    # 统计所有开放的端口
    global open_ports
    open_ports = []

    print("scan IP:%s" % target_ip)

    for port in scan_ports_from_file:  # 扫描端口范围从1到10001
        t = threading.Thread(target=scan_port, args=(port, target_ip))
        t.start()
        threads.append(t)

    # 等待所有线程执行完毕
    for t in threads:
        t.join()

    print("IP %s Open ports:%s" % (target_ip, open_ports))
    return (target_ip, open_ports)


# 扫描指定端口的函数
def scan_port(port, target_ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    
    try:
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            with lock:
                print("Port", port, "is open")
                open_ports.append(port)
    
    except (socket.timeout, ConnectionRefusedError):
        pass
    
    finally:
        sock.close()



# -------------------------------------------------------------------------------------------------------------------------
# 3 探测开放端口具体服务
# 对一个端口进行一次syn+ack扫描
# 输入一个ip与一个端口
def scan_port_with_version(target_ip, open_ports):
    
    # 存放已经扫过的端口
    scanned_ports = []

    # scan_port = {target_ip: {"service":[]}}
    # 一个ip所有端口的服务具体信息
    scan_port = {"services":[]}

    for target_port in open_ports:
        if target_port == 21:    # 不el  就会认为最后一个if前面是一个新的if然后最后又多输出一遍
            ftp_version = get_ftp_version(target_ip, target_port)
            scan_port["services"].append(ftp_version)

            # 扫描过的端口记录
            scanned_ports.append(target_port)
            

        # 直接探测 ssh 具体版本  还是socket牛逼
        elif target_port == 22:
            ssh_service = scan_port_ssh_version(target_ip, target_port)
            # scan_port[target_ip]["service"].append[ssh_version]
            scan_port["services"].append(ssh_service)

            # 扫描过的端口记录
            scanned_ports.append(target_port)

        # 23 端口暂时直接赋telnet
        elif target_port == 23:
            telnet_version = telnet_with_version(target_ip, target_port)
            scan_port["services"].append(telnet_version)

            # 扫描过的端口记录
            scanned_ports.append(target_port)

        # 80 端口暂时直接赋http
        elif target_port == 80:
            http_version = http_with_version(target_ip, target_port)
            
            # 若有设备指纹
            if http_version["service_app"] == "cisco":
                scan_port["deviceinfo"] = deviceinfo_with_version(target_ip, target_port)
                http_version["service_app"] = None   # 把app职位None
            # 这里pfsense直接识别
            elif http_version["service_app"] == "pfsense":
                scan_port["deviceinfo"] = ["firewall/pfsense"]
                http_version["service_app"] = ["nginx/N"]   # 暂时看到pfsense是nginx的不知道有没有别的
            scan_port["services"].append(http_version)

            # 扫描过的端口记录
            scanned_ports.append(target_port)

        # 443 端口暂时直接赋https
        elif target_port == 443:
            https_version = https_with_version(target_ip, target_port)
            scan_port["services"].append(https_version)

            # 扫描过的端口记录
            scanned_ports.append(target_port)

        # 3306端口开放直接认为是mysql
        elif target_port == 3306:
            mysql_version = mysql_with_version(target_ip, target_port)
            scan_port["services"].append(mysql_version)
            
            # 扫描过的端口记录
            scanned_ports.append(target_port)

        # 5672端口开放认为是ampq
        elif target_port == 5672:
            mysql_version = ampq_with_version(target_ip, target_port)
            scan_port["services"].append(mysql_version)
            
            # 扫描过的端口记录
            scanned_ports.append(target_port)

        # 6379端口开放直接认为是redis
        elif target_port == 6379:
            redis_version = redis_with_version(target_ip, target_port)
            scan_port["services"].append(redis_version)

            # 扫描过的端口记录
            scanned_ports.append(target_port)

        elif target_port == 15672:
            rabbitmq_version = rabbitMQ_with_version(target_ip, target_port)
            scan_port["services"].append(rabbitmq_version)

            # 扫描过的端口记录
            scanned_ports.append(target_port)

        # 一些常用端口且不要求版本号的，直接用socket的获取协议的库
        elif target_port == 25 or target_port == 110 or target_port == 111 or target_port == 143 or target_port == 445 or target_port == 554:
            common_ports_version = common_ports_with_version(target_ip, target_port)
            scan_port["services"].append(common_ports_version)

            # 扫描过的端口记录
            scanned_ports.append(target_port)

        # else:
        #     no_parse = future_parse(target_ip, target_port)
        #     scan_port["services"].append(no_parse)

    # 剩余端口，准备做更详细的扫描
    remain_ports = [x for x in open_ports if x not in scanned_ports]

    return scan_port, remain_ports
        
# 获取ftp版本信息 21
def get_ftp_version(target_ip, target_port):

    # 创建套接字
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # 设置连接超时时间为2秒
        client_socket.settimeout(2)

        # 连接到目标主机
        client_socket.connect((target_ip, target_port))

        # 接收版本信息
        response = client_socket.recv(1024)
        print("FTP版本信息:", response.decode())
        response = response.decode()

        # 里面有Pure-FTPd
        if "Pure-FTPd" in response:
            # 按照build 所要求的格式形成一个端口服务的内容
            result_dict = {
                "port": target_port,
                "protocol": "ftp",
                "service_app": ["Pure-FTPd/N"]
            }
        
        # 里面有FileZilla Server
        elif "FileZilla Server" in response:
            ftp_version = re.findall(r'(FileZilla Server.*?)\r\n', response)
            print(ftp_version)
            result_dict = {
                "port": target_port,
                "protocol": "ftp",
                "service_app": ftp_version
            }

        # 里面有vsFTPd
        elif "vsFTPd" in response:
            ftp_version = re.findall(r'\((.*?)\)', response)
            print(ftp_version)
            result_dict = {
                "port": target_port,
                "protocol": "ftp",
                "service_app": ftp_version
            }

        # 里面有CASwell
        elif "CASwell" in response:
            # 按照build 所要求的格式形成一个端口服务的内容
            result_dict = {
                "port": target_port,
                "protocol": "ftp",
                "service_app": ["CASwell/N"]
            }

        # 里面有ProFTPD
        elif "ProFTPD" in response:
            if "station" in response:
                # 按照build 所要求的格式形成一个端口服务的内容
                number = re.findall(r'station (.*?) Server', response)
                print(number)
                result_dict = {
                    "port": target_port,
                    "protocol": "ftp",
                    "service_app": ["ProFTPD"+"/"+number[0]]
                }
            else:
                # 220 ProFTPD Server (ProFTPD) 这样就直接取了
                result_dict = {
                    "port": target_port,
                    "protocol": "ftp",
                    "service_app": ["ProFTPD/N"]
                }

        # 按照build 所要求的格式形成一个端口服务的内容，其他待补充
        else:
            result_dict = {
                "port": target_port,
                "protocol": "ftp",
                "service_app": None
            }

        return result_dict

    except Exception as e:
        print("发生错误:", str(e))

        # 斟酌是直接认ftp还是不知道
        result_dict = {
            "port": target_port,
            "protocol": "ftp",
            "service_app": None
        }
        return result_dict

    finally:
        # 关闭套接字连接
        client_socket.close()


# 获取ssh版本信息 22
def scan_port_ssh_version(target_ip, target_port):
    # 创建 TCP 套接字
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # 设置连接超时时间为2秒
        sock.settimeout(2)

        # 尝试连接到目标主机
        sock.connect((target_ip, target_port))

        # 接收 SSH 服务器版本号
        version_data = sock.recv(1024)
        # version = version_data.decode().strip().split(" ")[0]  不确定ssh版本返回是否都是一种形式
        try:
            version = version_data.decode().strip()
            print("SSH version:", version)
            version = version.split(" ")

            result_dict = {
            "port": target_port,
            "protocol": "ssh",
            "service_app": version
            }  

            sock.close()

            return result_dict
        

        except:
            result_dict = {
            "port": target_port,
            "protocol": "ssh",
            "service_app": None
            }

            sock.close()

            return result_dict
        

        # 按照build 所要求的格式形成一个端口服务的内容

        # return result_dict

    except (socket.timeout, ConnectionRefusedError):
        print("Unable to connect or SSH is not running on the target host.")
        result_dict = {
            "port": target_port,
            "protocol": "ssh",
            "service_app": None
        }

        sock.close()
        return result_dict

    finally:
        # 关闭套接字
        sock.close()

# telnet 暂时返回telent 23
def telnet_with_version(target_ip, target_port):
    result_dict = {
        "port": target_port,
        "protocol": "telnet",
        "service_app": None
    }

    return result_dict

# http暂时直接返回http 80
def http_with_version(target_ip, target_port):
    
    # 经过测试发现大部分https证书都不对，用https全是报错，就加个443端口就行了
    if target_port == 443:
        url = "http://" + target_ip + ":443"
        protocol = "https"

    else:
        # 请求变成http://ip
        url = "http://" + target_ip
        protocol = "http"

    try:
        # 发送 HEAD 请求到指定 URL
        response = requests.head(url, timeout=5)

        # 提取服务器软件版本
        version = response.headers.get('Server')

        # 这里获取不到的话直接返回吧
        if version == None:
            result_dict = {
            "port": target_port,
            "protocol": protocol,
            "service_app": version
            }

            return result_dict

        print(version)
        version = version.strip(" ")

        # 这里有设备指纹，直接跳到设备
        if "cisco" in version:

            result_dict = {
            "port": target_port,
            "protocol": protocol,
            "service_app": "cisco"
            }

            return result_dict

        # web服务器指纹  这里到底用socket还是用requests还是有点纠结
        # 这里因为Sever显示的很复杂，所以想到检测/ 如果有/应该会是一致的服务+版本，如果不是那么就直接输出
        if "(" in version and ")" in version:
            if "OpenSSL" in version:
                if "PHP" in version:
                    version = version.split(" ")
                    try:
                        web_version = version[0]                            # web服务器版本
                        operation_version = version[1].strip("()")+"/N"     # 操作系统版本
                        openssl_version = version[2]
                        script_version = version[3]

                        result_dict = {
                        "port": target_port,
                        "protocol": protocol,
                        "service_app": [web_version, operation_version, openssl_version, script_version]
                        }
                    except:
                        result_dict = {
                        "port": target_port,
                        "protocol": protocol,
                        "service_app": version
                        }
                else:
                    version = version.split(" ")
                    try:
                        web_version = version[0]                            # web服务器版本
                        operation_version = version[1].strip("()")+"/N"     # 操作系统版本
                        openssl_version = version[2]

                        result_dict = {
                        "port": target_port,
                        "protocol": protocol,
                        "service_app": [web_version, operation_version, openssl_version]
                        }
                    except:
                        result_dict = {
                        "port": target_port,
                        "protocol": protocol,
                        "service_app": version
                        }
        # Werkzeug
            else:
                version = version.split(" ")
                try:
                    web_version = version[0]                            # web服务器版本
                    operation_version = version[1].strip("()")+"/N"     # 操作系统版本

                    result_dict = {
                    "port": target_port,
                    "protocol": protocol,
                    "service_app": [web_version, operation_version]
                    }
                except:
                    result_dict = {
                    "port": target_port,
                    "protocol": protocol,
                    "service_app": version
                    }
        # Werkzeug
        elif "Werkzeug" in version:
            version = version.split(" ")
            result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": version
            }
        
        elif "/" in version:
            # 带/的不知道能不能成
            result_dict = {
            "port": target_port,
            "protocol": protocol,
            "service_app": [version]
            }
        else:
            # Streamer 23.04 特殊构造
            if "Streamer" in version:
                version = version.split(" ")
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": [version[0]+"/"+version[1]]
                }
            # LiteSpeed
            elif "LiteSpeed" in version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": [version+"/N"]
                }
            # Caddy
            elif "Caddy" in version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": [version+"/N"]
                }
            # DNVRS-Webs
            elif "DNVRS-Webs" in version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": [version+"/N"]
                }
            # openresty
            elif "openresty" in version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": [version+"/N"]
                }

            # 不给版本号的nginx
            elif "nginx" in version:
                res = requests.get(url, timeout=5)

                if "pfsense" in res.text:
                    result_dict = {
                    "port": target_port,
                    "protocol": protocol,
                    "service_app": ["pfsense"]
                    }
                else:
                    result_dict = {
                    "port": target_port,
                    "protocol": protocol,
                    "service_app": [version+"/N"]
                    }
            # 不给版本号的Aapche
            elif "Apache" in version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": [version+"/N"]
                }
            # 这个请求头内容直接是server 
            elif "Kestrel" in version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": [version+"/N"]
                }
            elif "Varnish" in version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": [version+"/N"]
                }
            elif "Go" in version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": [version+"/N"]
                }
            # 这个跳转之后是nginx暂时就当他是nginx
            elif "BigIP" == version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": ["nginx/N"]
                }


            elif "server" == version:
                # 这里需要获取内容的版本信息了
                res = requests.get(url, timeout=5)

                # 解析页面内容
                soup = BeautifulSoup(res.text, 'html.parser')

                # 获取 <center> 标签的内容
                center_content = soup.find_all('center')
                print(center_content)
                version = center_content[1].text

                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": [version+"/N"]
                }
            elif "Dentamitra" == version:
                # 这里需要获取内容的版本信息了
                res = requests.get(url, timeout=5)

                # 解析页面内容
                soup = BeautifulSoup(res.text, 'html.parser')

                # 获取 <center> 标签的内容
                center_content = soup.find_all('center')
                print(center_content)
                version = center_content[1].text

                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": [version+"/N"]
                }

            elif "ArvanCloud" == version or "Frappe Cloud" == version or "Endouble" == version:
                # 这里需要获取内容的版本信息了
                res = requests.get(url, timeout=5)

                # 解析页面内容
                soup = BeautifulSoup(res.text, 'html.parser')

                # 获取 <center> 标签的内容
                center_content = soup.find_all('center')
                print(center_content)
                version = center_content[2].text

                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": [version+"/N"]
                }


            elif "blabla" == version:
                # 这里需要获取内容的版本信息了
                res = requests.get(url, timeout=5)

                # 解析页面内容
                soup = BeautifulSoup(res.text, 'html.parser')

                # 获取 <center> 标签的内容
                if " OpenResty" in soup:
                    result_dict = {
                    "port": target_port,
                    "protocol": protocol,
                    "service_app": ["openresty/N"]
                    }
                else:
                    result_dict = {
                    "port": target_port,
                    "protocol": protocol,
                    "service_app": None
                    }




            # 这里全部检查完最后直接归为None
            elif "sexmovies.co.il" in version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": None
                }
            elif "cdn" == version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": None
                }
            elif "xxxxxx" in version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": None
                }
            elif "se3" in version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": None
                }
            elif "HOSTVN.NET" == version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": None
                }
            elif "cloudflare" == version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": None
                }
            elif "Stellar Forces Web Server 1.93" == version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": None
                }
            elif "gunicorn" == version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": None
                }
            elif "psockets" == version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": None
                }
            elif "Appwrite" == version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": None
                }
            elif "WEB SERVER" == version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": None
                }
            elif "istio-envoy" == version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": None
                }
            elif "swoole-http-server" == version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": None
                }
            elif "Thinger.io" == version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": None
                }
            elif "AkamaiGHost" == version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": None
                }
            elif "webodigital" == version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": None
                }
            elif "rhino-core-shield" == version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": None
                }
            elif "Cowboy" == version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": None
                }
            elif "Web Server Core" == version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": None
                }                
            elif "uvicorn" == version:
                result_dict = {
                "port": target_port,
                "protocol": protocol,
                "service_app": None
                }
                            
            else:
                result_dict = {
                "port": target_port,
                "protocol": "http",
                "service_app": None
                }
            # 这里接下来是肯定有缺的

# ---------------------------------------------------------------------------------------------------------------------------

        print(result_dict)
        return result_dict

    except requests.exceptions.RequestException:
        # 如果连接超时，或者连接拒绝暂时都认为是http
        result_dict = {
        "port": target_port,
        "protocol": protocol,
        "service_app": None
        }
        
        return result_dict


#     # 创建 Socket 连接
#     sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     sock.settimeout(5)  # 设置超时时间为 5 秒

#     try:
#         # 连接到 Web 服务器的 80 端口
#         sock.connect((target_ip, 80))

#         # 发送 HTTP 请求头
#         request = b"HEAD / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n"
#         sock.sendall(request)

#         # 接收响应
#         response = sock.recv(1024).decode('utf-8')

#         # 解析服务器版本信息
#         version = None
# # ---------------------------------------------------------------------------------------------------------------------------
#         # web服务器指纹  这里到底用socket还是用requests还是有点纠结
#         for line in response.splitlines():
#             if "Server:" in line:
#                 version = line.split("Server:", 1)[1].strip()
#                 # 这里因为Sever显示的很复杂，所以想到检测/ 如果有/应该会是一致的服务+版本，如果不是那么就直接输出
#                 version = version.split(" ")
#                 try:
#                     web_version = version[0]                            # web服务器版本
#                     operation_version = version[1].strip("()")+"/N"     # 操作系统版本
                    
#                     result_dict = {
#                     "port": target_port,
#                     "protocol": "http",
#                     "service_app": [web_version, operation_version]
#                     }
#                 except:
#                     result_dict = {
#                     "port": target_port,
#                     "protocol": "http",
#                     "service_app": version
#                     }
#                 break
#             elif "server" in line:
#                 version = line.split("server:", 1)[1].strip()
#                 # Streamer 23.04 特殊构造
#                 if "Streamer" in version:
#                     version = version.split(" ")
#                     result_dict = {
#                     "port": target_port,
#                     "protocol": "http",
#                     "service_app": [version[0]+"/"+version[1]]
#                     }
#                 # LiteSpeed
#                 elif "LiteSpeed" in version:
#                     result_dict = {
#                     "port": target_port,
#                     "protocol": "http",
#                     "service_app": [version+"/N"]
#                     }
#                 # 这里接下来是肯定有缺的
#                 break
# # ---------------------------------------------------------------------------------------------------------------------------

#         if version == None:
#             result_dict = {
#             "port": target_port,
#             "protocol": "http",
#             "service_app": version
#             }

#         print(result_dict)
#         return result_dict

#     except (socket.timeout, ConnectionRefusedError, ConnectionResetError):
#         # 如果连接超时，或者连接拒绝暂时都认为是http
#         result_dict = {
#         "port": target_port,
#         "protocol": "http",
#         "service_app": None
#         }

#         return result_dict

#     finally:
#         # 关闭 Socket 连接
#         sock.close()


# https暂时直接返回https 443  这里，很多443用https无法访问，那就先尝试https访问，如果不行那就和普通的http一样
def https_with_version(target_ip, target_port):

    # 不是很确定有没有https需要特别请求获取才能得到openssl信息的,只是访问443端口那和普通http访问是一样的
    result_dict = http_with_version(target_ip, target_port)

    return result_dict

# mysql直接返回mysql 3306
def mysql_with_version(target_ip, target_port):
    # 创建 Socket 连接
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)  # 设置超时时间为 10 秒

    try:
        
        sock.connect((target_ip, target_port))

        # 发送 MySQL 握手数据
        handshake_data = b""

        sock.sendall(handshake_data)

        # 接收 MySQL 握手响应
        response = sock.recv(1024)
        print(response)

        # 打印响应
        version = re.findall("\\\\n(.*?)-", str(response))
        result_dict = {
            "port": target_port,
            "protocol": "mysql",
            "service_app": ["mysql/" + version[0]]
        }

        # 关闭 Socket 连接
        sock.close()

    except:
    
        result_dict = {
            "port": target_port,
            "protocol": "mysql",
            "service_app": None
        }
    
    finally:

        sock.close()

    return result_dict

# ampq 暂时认为5672端口
def ampq_with_version(target_ip, target_port):
    result_dict = {
        "port": target_port,
        "protocol": "ampq",
        "service_app": None
    }

    return result_dict

# redis直接返回redis 6379
def redis_with_version(target_ip, target_port):
    result_dict = {
        "port": target_port,
        "protocol": "redis",
        "service_app": None
    }

    return result_dict

# 15672 暂时直接认为是rabbitmq
def rabbitMQ_with_version(target_ip, target_port):
    result_dict = {
        "port": target_port,
        "protocol": "http",
        "service_app": ["rabbitmq/N"]
    }

    return result_dict

# 一些常用端口且不要求版本号的,直接根据socket获取
def common_ports_with_version(target_ip, target_port):
    protocolname = 'tcp'   # 只考察tcp
    protocol = socket.getservbyport(target_port, protocolname)
    
    result_dict = {
        "port": target_port,
        "protocol": protocol,
        "service_app": None
    }

    return result_dict

# 还没处理的暂时就先进这个函数写一下端口号
def future_parse(target_ip, target_port):

    # 按照build 所要求的格式形成一个端口服务的内容
    result_dict = {
        "port": target_port,
        "protocol": None,
        "service_app": None
    }
    
    return result_dict


# -------------------------------------------------------------------------------------------------------------------------
# 扫描剩余端口
def envdetector(ip=None, ports=''):
    if ip is None:
        ip = []
    ports = ports if ports else '20,21,22,3306,80,6379,8080'

    ip = [ip]
    ports = str(ports)

    config_list = serviceDetector(ip, ports)
    # if ip_self not in hosts:        # 做为网络中的存活主机，宿主机的ip应该在hosts列表中
    #     hosts.append(ip_self)

    return config_list

def serviceDetector(hosts, ports='20,21,22,3306,80,6379,8080,2222'):
    """
    探测主机列表指定端口的服务
    :param hosts: 指定主机列表
    :param ports: 端口号
    :return: 各个主机的服务，返回字典
    """
    config_list = {}
    print('[+] 服务扫描开始......')
    nm = nmap.PortScanner()
    nm.scan(' '.join(hosts), arguments='-sV -T 4 -p '+ports)

    for ip in hosts:
        try:
            hostInfo = nm[ip]
            if hostInfo.state() == 'up':
                config = get_config(hostInfo)
                config_list.update(config)
        except:
            pass

    print('[+] 服务扫描结束')
    return config_list

def get_config(hostInfo):
    config = {}
    service = []
    if hostInfo.all_protocols():
        for protocol in hostInfo.all_protocols():
            host = hostInfo[protocol]
            if host:
                for port in host.keys():
                    h = host[port]
                    if h['name'] == "http" or h['name'] == "https" or h['name'] == "mysql" or h['name'] == "redis" or h['name'] == "ftp" or h['name'] == "smtp" or h['name'] == "ssh" or h['name'] == "telnet" or h['name'] == "rtsp" or h['name'] == "amqp" or h['name'] == "mongodb":
                        if h['version'] != '':
                            service.append(dict([
                                ('port', port),
                                ('protocol', h['name']),
                                ('service_app', [h['product']+"/"+h['version']])
                            ]))
                        elif h['product'] == 'nginx':
                            service.append(dict([
                                ('port', port),
                                ('protocol', h['name']),
                                ('service_app', [h['product']+"/N"])
                            ]))
                        elif h['name'] == 'rtsp':
                            service.append(dict([
                                ('port', port),
                                ('protocol', h['name']),
                                ('service_app', None)
                            ]))
                        else:
                            service.append(dict([
                                ('port', port),
                                ('protocol', h['name']),
                                ('service_app', [h['product']])
                            ]))
                    else:
                        service.append(dict([
                            ('port', port),
                            ('protocol', None),
                            ('service_app', None)
                        ]))

    config.update({'services': service})

    return config



# -------------------------------------------------------------------------------------------------------------------------
# 4 设备指纹
def deviceinfo_with_version(target_ip, target_port):
    # 通过http来获得设备信息
    # 请求变成http://ip
    url = "http://" + target_ip

    
    try:
        # 发送 HEAD 请求到指定 URL
        response = requests.head(url, timeout=5)

        # 提取服务器软件版本
        version = response.headers.get('Server')

        # 这里获取不到的话直接返回吧
        if version == None:
            return None
        
        print(version)
        version = version.strip(" ")

        # 这里有设备指纹，直接跳到设备
        if "cisco" in version:
            return [version]

    except requests.exceptions.RequestException:
        return None


# -------------------------------------------------------------------------------------------------------------------------
# 5 蜜罐识别
class HoneyDetector:
    def __init__(self, dst_host, dst_port):
        self.dst_host = dst_host
        self.dst_port = dst_port

    def detect_glastopf(self):
        # web服务
        honey_type = "glastopf"
        try:
            url = "http://" + self.dst_host + ":" + self.dst_port
            r = requests.get(url, timeout=5)
            if "Login Form" in r.text and "My Resource" in r.text and "She was still" in r.text:
                return honey_type, True
            else:
                return honey_type, False
        except:
            return honey_type, False

    def detect_kippo(self):
        # ssh服务
        kippo_type = "kippo"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((self.dst_host, int(self.dst_port)))
            banner = s.recv(1024)
            s.send(b'\n\n\n\n\n\n\n\n')
            response = s.recv(1024)
            s.close()
            if b"168430090" in response:
                return kippo_type, True
            # 创建SSH客户端对象
            ssh = paramiko.SSHClient()

            # 添加远程主机的公钥（如果是第一次连接的话）
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # kippo默认口令
            ssh.connect(self.dst_host, port=int(self.dst_port), username='root', password='123456')
            transport = ssh.get_transport()
            if transport.is_active():
                return kippo_type, True
        except:
            return kippo_type, False
        try:
            # 创建SSH客户端对象
            ssh = paramiko.SSHClient()

            # 添加远程主机的公钥（如果是第一次连接的话）
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # kippo默认口令
            ssh.connect(self.dst_host, port=int(self.dst_port), username='root', password='root')
            transport = ssh.get_transport()
            if transport.is_active():
                return "hfish", True
        except:
            return "hfish", False
    def hfish_Web(self):
        # web服务
        honey_type = "hfish"
        try:
            url = "http://" + self.dst_host + ":" + self.dst_port
            r = requests.get(url + "/noexistpage_001", timeout=5)
            if r.status_code == 404 and r.text == "404 page not found":
                return honey_type, True
            r2 = requests.get(url + "/x.js", timeout=5)
            if r2.status_code == 200 and "sec_key" in r2.text:
                return honey_type, True
            return honey_type, False
        except:
            return honey_type, False

    def hfish_redis(self):
        honey_type = "hfish"
        redis_host = self.dst_host
        redis_port = int(self.dst_port)
        redis_password = '123456'  # 将 'your_redis_password' 替换为实际的Redis密码
        timeout_seconds = 3  # Set the desired timeout value in seconds

        try:
            # 尝试连接到Redis服务器并使用口令进行身份验证
            redis_client = redis.StrictRedis(host=redis_host, port=redis_port, password=redis_password,socket_connect_timeout=timeout_seconds,socket_timeout=timeout_seconds)

            # 尝试执行一个简单的操作（例如：检查Redis服务器是否在线）
            redis_client.ping()

            # 如果上述操作没有引发异常，表示成功通过身份认证
            return honey_type, True

        except:
            # 身份认证失败
            return honey_type, False

    def hfish_mysql(self):
        honey_type = "hfish"
        mysql_host = self.dst_host
        mysql_user = "root"
        mysql_port = int(self.dst_port)
        mysql_password = 'root'  # 将 'your_redis_password' 替换为实际的Redis密码

        try:
            # 尝试连接到MySQL数据库
            connection = pymysql.connect(
                host=mysql_host,
                user=mysql_user,
                password=mysql_password,
                connect_timeout=3
            )

            # 如果连接成功，返回连接对象
            return honey_type, True

        except:
            # 连接失败，返回None
            return honey_type, False

    def hfish_Telnet(self):
        honey_type = "hfish"
        host = self.dst_host
        port = int(self.dst_port)

        try:
            # 尝试建立Telnet连接
            tn = telnetlib.Telnet(host, port, timeout=3)

            # 尝试读取登录后的提示信息
            login_output = tn.read_until(b"\n", timeout=3)

            # 如果登录后的提示信息中没有包含"Login failed"等关键字，则认为连接成功
            if b"Login failed" not in login_output and b"Access denied" not in login_output:
                return honey_type, True
            else:
                return honey_type, False

        except Exception as e:
            # 连接过程中发生异常，返回False
            return honey_type, False

    def hfish_ftp(self):
        honey_type = "hfish"
        host = self.dst_host
        name = "root"
        password = "root"
        port = int(self.dst_port)

        try:
            # 连接到FTP服务器
            ftp = FTP()
            ftp.connect(host, port, timeout=3)

            # 登录到FTP服务器
            ftp.login(name, password)

            # 登录成功，退出FTP连接并返回True
            ftp.quit()
            return honey_type, True

        except Exception as e:
            # 登录失败或连接出错，返回False
            return honey_type, False


# 合并json
# 获取当前路径
def mege_json():
    current_path = os.getcwd()

    # 存储所有 JSON 文件的内容
    merged_data = []

    # 遍历当前路径下的所有文件
    print(current_path)
    for file_name in os.listdir(current_path):
        print(file_name)
        if file_name.endswith(".json"):
            file_path = os.path.join(current_path, file_name)
            with open(file_path, 'r') as file:
                try:
                    data = json.load(file)
                    merged_data.append(data)
                except json.JSONDecodeError:
                    print(f"JSON 解析错误：{file_path}")

    # 将合并后的数据写入新的 JSON 文件
    output_file = "merged.json"  # 合并后的 JSON 文件名
    with open(output_file, 'w') as file:
        json.dump(merged_data, file, indent=4)

    print(f"合并完成，已生成 {output_file} 文件。")


def main():
    ips_from_file = open("ips.txt", "r")
    for each_ips_in_file in ips_from_file.readlines():
        print(each_ips_in_file.strip("\n"))

        # 1、探测存活主机
        # ip = input("请输入网段(例如16.163.13.0/24):")
        ip = each_ips_in_file.strip("\n")
        ip = ip.split('/')[0][:-1]
        alive_PC = scan_alive_ip(ip).keys()  # 返回存活主机列表
        print("主机存活探测完成")

        # target_ip = input("Enter the target IP address: ")
        target_ip = alive_PC
        print(target_ip)


        # 2、对每个主机扫描端口扫描
        PC_Open_Ports = {}  # 最后记录主机和开放端口

        for each in target_ip:
            temp = scan_ports(each)
            PC_Open_Ports[temp[0]] = temp[1]
        print("端口扫描完成")
        print(PC_Open_Ports)

        # 将扫描好的主机和开放端口缓存，以备后面时间不够，直接扫存活主机和开放端口
        cache_file_name = each_ips_in_file.split("/")[0]
        with open(cache_file_name+".txt", "w") as cache_pc:
            cache_pc.write(str(PC_Open_Ports))
        cache_pc.close()

        # 3、对每个主机开放的端口进行扫描
        result = {}

        # each_ips_in_file = "159.65.5.0/24"
        # test_result = {'159.65.5.1': [], '159.65.5.11': [80, 12443], '159.65.5.7': [21, 80, 443, 22, 3306], '159.65.5.23': [22, 443], '159.65.5.15': [22, 443, 80, 7080], '159.65.5.2': [22, 80, 443], '159.65.5.10': [22, 8080], '159.65.5.12': [21, 443, 25, 80, 22, 3306], '159.65.5.28': [8080, 8443, 8880], '159.65.5.13': [22, 3306, 8080, 9100], '159.65.5.32': [22, 80], '159.65.5.19': [22, 80, 443], '159.65.5.20': [22, 80, 3306], '159.65.5.27': [22, 443, 80], '159.65.5.25': [22], '159.65.5.40': [22, 80, 443], '159.65.5.9': [], '159.65.5.21': [80, 22, 3306], '159.65.5.33': [22, 443, 80], '159.65.5.54': [22], '159.65.5.60': [22, 80, 443, 9100], '159.65.5.24': [22, 25, 80, 3306, 8083], '159.65.5.67': [22, 80], '159.65.5.29': [80, 443, 22], '159.65.5.76': [22], '159.65.5.62': [22, 443, 80], '159.65.5.88': [22, 3306, 9100], '159.65.5.39': [80, 3306, 22, 443], '159.65.5.48': [22, 443, 80], '159.65.5.80': [80, 443], '159.65.5.103': [443, 8080], '159.65.5.101': [22], '159.65.5.107': [22], '159.65.5.97': [22, 80, 443], '159.65.5.70': [22, 80, 443, 7080], '159.65.5.79': [80, 443, 22], '159.65.5.125': [80, 22], '159.65.5.89': [80, 443, 22], '159.65.5.136': [80, 443, 22, 888, 8080], '159.65.5.119': [22, 443, 80, 3128, 8080, 8081, 8880], '159.65.5.105': [8081, 8083, 8085, 8086, 8082, 8888], '159.65.5.140': [22, 443, 80, 9001], '159.65.5.106': [22, 443, 3306, 80, 8080], '159.65.5.66': [80, 443, 22], '159.65.5.152': [22, 443, 80, 3000], '159.65.5.71': [22, 10000], '159.65.5.147': [22], '159.65.5.135': [22, 3000, 8086, 8088], '159.65.5.124': [80, 443], '159.65.5.132': [22], '159.65.5.177': [21, 22, 80, 25, 7080, 8090], '159.65.5.73': [22, 443, 80], '159.65.5.144': [22, 80], '159.65.5.134': [22, 80, 443], '159.65.5.173': [80, 443, 22], '159.65.5.26': [80, 443], '159.65.5.143': [22, 443, 80], '159.65.5.146': [22, 80], '159.65.5.122': [22, 80, 443, 10010], '159.65.5.180': [22], '159.65.5.117': [22, 80, 443, 2379, 10250], '159.65.5.215': [22, 80, 10000], '159.65.5.90': [22, 21, 25, 80, 443, 8443, 8880], '159.65.5.59': [80, 22, 443], '159.65.5.81': [21, 22, 443], '159.65.5.178': [22], '159.65.5.200': [22, 80, 443], '159.65.5.118': [22, 80, 443, 5432], '159.65.5.43': [22, 8080], '159.65.5.231': [80], '159.65.5.229': [80, 5432, 443, 8081], '159.65.5.57': [80, 888, 8888], '159.65.5.170': [22, 80, 443], '159.65.5.185': [22, 80], '159.65.5.255': [22, 80, 443], '159.65.5.249': [22], '159.65.5.194': [80, 443, 22, 3306], '159.65.5.150': [22, 443, 80, 3306], '159.65.5.115': [22], '159.65.5.195': [22, 80, 3128, 8080, 8000, 8880], '159.65.5.189': [22, 80, 3306, 9100], '159.65.5.110': [22, 80, 443, 3000], '159.65.5.234': [22, 8080, 7890, 7001, 9091], '159.65.5.205': [22, 25, 80, 443], '159.65.5.223': [21, 25, 80, 443, 3306, 7080], '159.65.5.46': [22], '159.65.5.52': [22, 80], '159.65.5.240': [], '159.65.5.86': [22], '159.65.5.137': [22, 80], '159.65.5.222': [21, 80, 22, 443, 888], '159.65.5.227': [22, 80], '159.65.5.165': [22, 8080], '159.65.5.68': [22, 80], '159.65.5.116': [80], '159.65.5.176': [22, 443, 80], '159.65.5.244': [21, 22, 25, 80, 443, 7080], '159.65.5.83': [22, 80, 443, 8080], '159.65.5.193': [21, 22, 25, 443, 80, 7080, 8090], '159.65.5.243': [22, 21, 80, 443, 25, 7080, 8090], '159.65.5.156': [22, 21, 25, 80, 443], '159.65.5.218': [22], '159.65.5.186': [22, 80, 3306], '159.65.5.148': [22, 80, 443], '159.65.5.120': [21, 80, 443, 25, 3306], '159.65.5.202': [22, 80], '159.65.5.235': [22, 80, 443], '159.65.5.187': [22, 80, 443], '159.65.5.224': [22, 80, 443], '159.65.5.34': [22, 80, 443], '159.65.5.155': [22, 80, 10000], '159.65.5.51': [25, 80, 3306], '159.65.5.64': [80], '159.65.5.109': [80], '159.65.5.174': [22, 80, 443], '159.65.5.171': [22], '159.65.5.47': [443, 80, 22], '159.65.5.84': [80, 443, 22], '159.65.5.226': [80, 22, 3306], '159.65.5.242': [22, 80, 443], '159.65.5.112': [80, 22, 443, 3306], '159.65.5.18': [80, 443, 22], '159.65.5.188': [22, 80, 25, 3306], '159.65.5.139': [22, 80, 443, 8090, 9100], '159.65.5.149': [], '159.65.5.250': [22, 80, 443, 8080], '159.65.5.104': [22, 443, 80], '159.65.5.128': [22, 80], '159.65.5.14': [22, 80], '159.65.5.38': [22, 21, 80, 443, 25, 8443, 8880], '159.65.5.183': [22, 443, 80], '159.65.5.85': [22, 80, 443, 8001, 8000], '159.65.5.192': [22, 80, 3306, 8000, 8002, 8001, 8070, 8060, 8080, 9000], '159.65.5.129': [80, 21, 22, 25, 443, 3306], '159.65.5.207': [22], '159.65.5.98': [22, 80], '159.65.5.113': [22, 80, 443], '159.65.5.233': [22, 80, 3000], '159.65.5.61': [21, 25, 80, 22, 3306, 443], '159.65.5.217': [21, 80, 443], '159.65.5.130': [22], '159.65.5.77': [21, 80, 22], '159.65.5.94': [443, 80, 21, 22, 888], '159.65.5.236': [22, 80, 443], '159.65.5.123': [], '159.65.5.197': [22], '159.65.5.35': [22, 25, 80, 21, 443, 8880], '159.65.5.87': [], '159.65.5.221': [22], '159.65.5.237': [], '159.65.5.230': [22, 80, 443], '159.65.5.74': [80, 443], '159.65.5.232': [21, 22, 80, 443, 8443, 8880], '159.65.5.133': [22], '159.65.5.22': [80, 22, 443], '159.65.5.245': [], '159.65.5.247': [22], '159.65.5.126': [22, 9001], '159.65.5.158': [22, 80], '159.65.5.72': [22, 80], '159.65.5.167': [25, 80, 443, 21, 22], '159.65.5.163': [443, 22, 80, 21], '159.65.5.196': [22, 9001], '159.65.5.238': [22, 80, 3000], '159.65.5.211': [22, 80, 443], '159.65.5.203': [], '159.65.5.181': [25, 22, 80, 443, 21, 3306, 8083], '159.65.5.216': [25, 80, 22, 3306, 443], '159.65.5.210': [443, 80, 22, 3306]}

        for each_ip, ports in PC_Open_Ports.items():
            print("identification IP: %s" % each_ip)
            temp, remain_temp = scan_port_with_version(each_ip, ports)
                
            # 出一个remain列表，然后走nmap 扫描，只扫http和ssh
            if remain_temp != []:
                print(remain_temp)
                for each_port in remain_temp:
                    remain_service = envdetector(each_ip, each_port)  # 用nmap扫描剩余的端口
                    print(remain_service)
                    if remain_service != {}:
                        temp["services"].extend(remain_service["services"]) # 合并列表

            # 设备识别，暂时是从http页面识别过来
            try:
                temp["deviceinfo"]
            except:
                temp["deviceinfo"] = None   # 后续作为识别ip设备入口  或者在下面继续新开
            

            # 蜜罐识别，暂时根据ssh和http来
            print(temp["services"])
            ssh_ports = [service["port"] for service in temp["services"] if service.get("protocol") == "ssh"]    # 获取所有服务中的ssh端口
            http_ports = [service["port"] for service in temp["services"] if service.get("protocol") == "http"]  # 获取所有服务中的http端口
            redis_ports = [service["port"] for service in temp["services"] if service.get("protocol") == "redis"] # 获取所有服务中redis端口
            ftp_ports = [service["port"] for service in temp["services"] if service.get("protocol") == "ftp"]  # 获取所有服务中ftp端口
            mysql_ports = [service["port"] for service in temp["services"] if service.get("protocol") == "mysql"]  # 获取所有服务中mysql端口
            telnet_ports = [service["port"] for service in temp["services"] if service.get("protocol") == "telnet"]  # 获取所有服务中mysql端口
            print(ssh_ports)
            print(http_ports)
            print(redis_ports)
            print(ftp_ports)
            print(mysql_ports)
            print(telnet_ports)

            honey = []

            if ssh_ports != []:
                for each_port in ssh_ports:
                    each_port = str(each_port)
                    De = HoneyDetector(each_ip, each_port)

                    honey_result = De.detect_kippo()

                    if honey_result[1] == True:
                        honey.append(each_port + "/" + honey_result[0])
                    else:
                        pass
            
            if http_ports != []:
                for each_port in http_ports:
                    each_port = str(each_port)
                    De = HoneyDetector(each_ip, each_port)

                    honey_result = De.detect_glastopf()

                    if honey_result[1] == True:
                        honey.append(each_port + "/" + honey_result[0])
                    else:
                        pass

                    honey_result = De.hfish_Web()

                    if honey_result[1] == True:
                        honey.append(each_port + "/" + honey_result[0])
                    else:
                        pass

            if redis_ports != []:
                for each_port in redis_ports:
                    each_port = str(each_port)
                    De = HoneyDetector(each_ip, each_port)

                    honey_result = De.hfish_redis()

                    if honey_result[1] == True:
                        honey.append(each_port + "/" + honey_result[0])
                    else:
                        pass

            if ftp_ports != []:
                for each_port in ftp_ports:
                    each_port = str(each_port)
                    De = HoneyDetector(each_ip, each_port)

                    honey_result = De.hfish_ftp()

                    if honey_result[1] == True:
                        honey.append(each_port + "/" + honey_result[0])
                    else:
                        pass

            if mysql_ports != []:
                for each_port in mysql_ports:
                    each_port = str(each_port)
                    De = HoneyDetector(each_ip, each_port)

                    honey_result = De.hfish_mysql()

                    if honey_result[1] == True:
                        honey.append(each_port + "/" + honey_result[0])
                    else:
                        pass

            if telnet_ports != []:
                for each_port in telnet_ports:
                    each_port = str(each_port)
                    De = HoneyDetector(each_ip, each_port)

                    honey_result = De.hfish_Telnet()

                    if honey_result[1] == True:
                        honey.append(each_port + "/" + honey_result[0])
                    else:
                        pass

            if honey == []:
                temp["honeypot"] = None
            else:
                temp["honeypot"] = honey

            # if ssh_ports == [] and http_ports == []:
            #     temp["honeypot"] = None
            # elif http_ports == [] and ssh_ports != []:
            #     for ssh_port in ssh_ports:
            #         ssh_port = str(ssh_port)
            #         De = HoneyDetector(each_ip, ssh_port)

            #         honey_result = De.detect_kippo() # 检测是否为kippo蜜罐
                    
            #         if honey_result[1] == True:
            #             temp["honeypot"] = [http_port+"/"+honey_result[0]]
            #             break
            #         else:
            #             temp["honeypot"] = None
            # elif ssh_ports == [] and http_ports != []:
            #     for http_port in http_ports:
            #         http_port = str(http_port)
            #         De = HoneyDetector(each_ip, http_port)

            #         honey_result = De.detect_glastopf()
            #         if honey_result[1] == True:
            #             temp["honeypot"] = [http_port+"/"+honey_result[0]]
            #             break
            #         else:
            #             honey_result = De.hfish_Web()
            #             if honey_result[1] == True:
            #                 temp["honeypot"] = [http_port+"/"+honey_result[0]]
            #                 break
            #             else:
            #                 temp["honeypot"] = None
            # else:
            #     for ssh_port in ssh_ports:
            #         ssh_port = str(ssh_port)
            #         De = HoneyDetector(each_ip, ssh_port)

            #         honey_result = De.detect_kippo() # 检测是否为kippo蜜罐

            #         print(honey_result)
            #         # 这里就认为一个主机只可能是一种蜜罐
            #         if honey_result[1] == True:
            #             temp["honeypot"] = [ssh_port+"/"+honey_result[0]]
            #             break
            #         else:
            #             for http_port in http_ports:
            #                 http_port = str(http_port)
            #                 De = HoneyDetector(each_ip, http_port)

            #                 honey_result = De.detect_glastopf()
            #                 if honey_result[1] == True:
            #                     temp["honeypot"] = [http_port+"/"+honey_result[0]]
            #                     break
            #                 else:
            #                     honey_result = De.hfish_Web()
            #                     if honey_result[1] == True:
            #                         temp["honeypot"] = [http_port+"/"+honey_result[0]]
            #                         break
            #                     else:
            #                         temp["honeypot"] = None


            # temp["honeypot"] = None     # 后续作为识别ip该属性入口


            print(each_ip+":"+str(temp))
            result[each_ip] = temp

        print(result)
        # 将数据转换为 JSON 格式的字符串
        json_data = json.dumps(result)

        print(json_data)

        file_name = each_ips_in_file.split("/")[0]
        with open(file_name+".json", "w") as result_file:
            result_file.write(json_data)
        result_file.close()

    ips_from_file.close()
    

if __name__ == '__main__':
    main()
    mege_json()