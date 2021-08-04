import asyncio
import hashlib
import json
import logging
import ssl
from asyncio import ensure_future
from client_config.config import *

heart_flag = 1


def transfer_json(msg, method):
    """字符串与json格式互相转换"""
    if method:
        return json.dumps(msg)
    else:
        return json.loads(msg)


async def client_authenticate(reader, writer, secret_key):
    """客户端认证"""
    message = await reader.read(1024)
    s = hashlib.sha512()
    s.update(message + secret_key.encode('utf-8'))  # 加密
    digest = s.hexdigest()
    writer.write(digest.encode())
    await writer.drain()


async def user_login(reader, writer):
    global username
    """用户认证与注册"""
    username = USER[0][0]
    password = USER[0][1]
    account = {'username': username, 'password': password}
    account = transfer_json(account, True)
    writer.write(account.encode())
    await writer.drain()
    ensure_account = await reader.read(1024)
    ensure_account = ensure_account.decode()
    if ensure_account == 'Login Success':
        print('-----用户登陆成功！-----')
        logging.info(f"用户：{username} 登录成功")
        return True
    elif ensure_account == 'Need Email':
        email = input("请输入注册的邮箱地址：")
        writer.write(email.encode())
        await writer.drain()
        ensure_register = await reader.read(1024)
        ensure_register = ensure_register.decode()
        if ensure_register == 'Register Success':
            print('-----用户注册成功！-----')
            logging.info(f"用户：{username} 注册成功")
            return True
        else:
            print("-----用户注册失败！-----")
            logging.error(f"用户：{username}注册失败")
            return False
    else:
        return False


def create_client_ssl():
    """生成ssl"""
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.options |= ssl.OP_NO_TLSv1
    ssl_ctx.options |= ssl.OP_NO_TLSv1_1
    ssl_ctx.load_cert_chain(certfile='./client_ssl./mycertfile.pem', keyfile='./client_ssl./mykeyfile.pem')
    ssl_ctx.load_verify_locations(cafile='./client_ssl./mycertfile.pem')
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.VerifyMode.CERT_REQUIRED
    ssl_ctx.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')
    return ssl_ctx


async def handle_func(l_reader, l_writer):
    global heart_flag
    heart_flag = 0
    writer.write('start_server'.encode())
    await writer.drain()
    asyncio.ensure_future(port_transmit_other(l_reader, writer))
    asyncio.ensure_future(port_transmit_server(reader, l_writer))
    global writer1, writer2
    writer1 = l_writer.get_extra_info('peername')
    writer2 = l_writer.get_extra_info('sockname')


async def port_transmit_other(l_reader, writer):
    """端口流量转发"""
    while True:
        try:
            data = await l_reader.read(1024)
            # data = data.decode()
            print('接受到端口流量数据...')
            logging.info(f"端口收到外部请求数据：{data} {writer1}----->{writer2}")
            if data == b'' or data == b'exit':
                break
            writer.write(data)
            await writer.drain()
            print('转发至代理服务器...')
            logging.info(f"转发数据至代理服务器{writer.get_extra_info('sockname')}----->{writer.get_extra_info('peername')}")
        except ConnectionResetError:
            print('与服务器的连接已断开！')
            logging.error("与服务器的连接已断开")
            break


async def port_transmit_server(reader, l_writer):
    """接受回复"""
    while True:
        try:
            data = await reader.read(1024)
            # data = data.decode()
            if data == b'':
                l_writer.close()
                # print('2与服务器的连接已断开！')
                break
            if data == b'Heart beat!':
                print('收到心跳回应' + str(data))
                logging.info(f"来自：{writer.get_extra_info('peername')}的{data}响应\
                 {writer.get_extra_info('peername')}----->{writer.get_extra_info('sockname')}")
                continue
            print('收到回复：' + str(data))
            logging.info(f"收到回复{writer.get_extra_info('peername')}----->{writer.get_extra_info('sockname')}")
            l_writer.write(data)
            print('转发回复：' + str(data))
            logging.info(f"端口转发数据:{l_writer.get_extra_info('sockname')}----->{writer1}\n{data}")
        except Exception as e:
            l_writer.close()
            #print(e)
            logging.error("服务器强制断开")
            print('3与服务器的连接已断开！')
            logging.error("3与服务器的连接已断开！")
            break


async def heartbeat(reader, writer):
    while True:
        try:
            await asyncio.sleep(10)
            if writer.get_extra_info('sockname') is None:
                break
            print(f"发送：Heart beat!")
            logging.info(f"发送：Heart beat!")
            print(f"{writer.get_extra_info('sockname')}----->{writer.get_extra_info('peername')}")
            logging.info(f"{writer.get_extra_info('sockname')}----->{writer.get_extra_info('peername')}")
            writer.write('Heart beat!'.encode())
            await writer.drain()
            if heart_flag == 1:
                re_heart = await reader.read(1024)
                print('收到心跳回应' + re_heart.decode())
                logging.info(f"收到心跳回应：{writer.get_extra_info('peername')}---->{writer.get_extra_info('sockname')}")
        except ConnectionResetError:
            break


async def _init():
    """初始化，连接服务器，客户端认证，用户认证"""
    try:
        global reader, writer
        ssl_client = create_client_ssl()
        reader, writer = await asyncio.open_connection(Server_Ip[0], Server_Port[0], ssl=ssl_client)
        print(f"本地客户端地址：{writer.get_extra_info('sockname')}")
        await client_authenticate(reader, writer, SECRET_KEY)
        login_result = await user_login(reader, writer)
        if not login_result:
            print("请求登陆失败！")
            logging.warning(f"{username}:登录失败")
            raise ConnectionResetError
        client_addr = writer.get_extra_info('sockname')
        client_ip, client_port = client_addr[0], client_addr[1]
        return reader, writer, client_ip, client_port
    except ConnectionAbortedError:
        logging.error("ConnectionAbortedError：服务端连接不上")




async def tcp_echo_client():
    """主函数"""
    global reader,writer,server
    try:
        reader, writer, client_ip, client_port = await _init()  # 初始化

        ident = {'client_ip': client_ip, 'client_port': client_port, 'other': 'hello'}
        ident_json = json.dumps(ident)
        writer.write(ident_json.encode())
        await writer.drain()

        wait_config = await reader.read(1024)
        print(wait_config.decode())

        config_rule_json = await reader.read(1024)
        config_rule = json.loads(config_rule_json)  # 获取服务器下发的规则
        # print(config_rule)
        if config_rule['ident'] == 'OK':
            writer.write(config_rule_json)
            await writer.drain()

        ident, src_ip, src_port, dst_ip, dst_port = \
            config_rule['ident'], config_rule['src_ip'], \
            config_rule['src_port'], config_rule['dst_ip'], config_rule['dst_port'],

        ensure_future(heartbeat(reader, writer))

        server = await asyncio.start_server(handle_func, src_ip, int(src_port))
        addr = server.sockets[0].getsockname()
        print('已开启本地端口{}流量转发...\n'.format(addr[1]))
        logging.info(f"已开启本地端口{addr[1]}流量转发...\n")
        async with server:
            await server.serve_forever()



    except ConnectionRefusedError:
        logging.info("目标服务器未开启...请重试")
        print("目标服务器未开启...请重试")
    except json.decoder.JSONDecodeError:
        print('5与服务器的连接已断开！')
        logging.info("与服务器的连接已断开")
    except ConnectionResetError:
        print('6与服务器的连接已断开！')
        logging.error("与服务器的连接已断开")
    except RuntimeError:
        pass
    except TypeError:
        logging.error("服务器未开启")


def start_connect():
    logging.basicConfig(level=logging.DEBUG,  # 控制台打印的日志级别
                        filename='client.log',
                        filemode='w',  # 模式，有w和a，w就是写模式，每次都会覆盖之前的日志 a是追加模式，默认a
                        format='%(asctime)s - %(pathname)s[line:%(lineno)d] - %(levelname)s: %(message)s'
                        # 日志格式
                        )
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())


if __name__ == '__main__':
    start_connect()
