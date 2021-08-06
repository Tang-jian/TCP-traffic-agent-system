import configparser
import os


root_dir = os.path.dirname(__file__)  # 获取当前工作目录
configpath = os.path.join(root_dir, "config.ini")
cf = configparser.ConfigParser()
cf.read(configpath,encoding="utf-8") # 读取配置文件

#获取用户信息
username = (cf.get("user","username")).strip()
password = (cf.get("user","password")).strip()
email = (cf.get("user","email")).strip()

#获取服务器地
server_IP = cf.get("server","server_IP")
server_port = cf.getint("server","server_port")

#获取秘钥
SECRET_KEY = (cf.get("key","SECRET_KEY")).strip()
