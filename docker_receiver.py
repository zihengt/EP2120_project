import socket
import struct
import random
import time
import csv  # 用于数据记录
from enum import Enum
import select  # 导入 select 模块

# 定义服务器状态
class ServerState(Enum):
    INITIAL = 1
    HANDSHAKE = 2
    CONNECTED = 3
    CLOSED = 4

# 常量
bind_ip = '172.20.0.3'
bind_port = 12346  # 初始绑定端口
additional_ports = [12347]  # 迁移后的端口列表
DATA_LOSS_PROBABILITY = 0.1  # 数据包丢失概率
ACK_LOSS_PROBABILITY = 0.1  # ACK 丢失概率

# 模拟网络延迟（秒）
SIMULATED_NETWORK_DELAY = 0.05  # 50毫秒

# 数据记录文件
receiver_log_file = 'receiver_log.csv'

# QUIC数据包头部解析函数
def parse_quic_header(data):
    index = 0
    packet_type = data[index]
    index += 1
    packet_number = struct.unpack('!I', data[index:index + 4])[0]
    index += 4
    dest_conn_id_len = struct.unpack('!H', data[index:index + 2])[0]
    index += 2
    dest_conn_id = data[index:index + dest_conn_id_len]
    index += dest_conn_id_len
    src_conn_id_len = struct.unpack('!H', data[index:index + 2])[0]
    index += 2
    src_conn_id = data[index:index + src_conn_id_len]
    index += src_conn_id_len
    header_size = index
    payload = data[header_size:]
    return packet_type, packet_number, dest_conn_id, src_conn_id, payload

# STREAM帧解析函数
def parse_stream_frame(data):
    if len(data) < 9:
        raise ValueError("数据长度不足以解析STREAM帧头部")
    frame_type, stream_id, offset, payload_length = struct.unpack('!BHIH', data[:9])
    if len(data) < 9 + payload_length:
        raise ValueError("数据长度不足以解析STREAM帧负载")
    payload = data[9:9 + payload_length]
    return frame_type, stream_id, offset, payload

# MAX_STREAM_DATA帧创建函数
def create_max_stream_data_frame(stream_id, max_stream_data):
    frame_type = 0x11  # MAX_STREAM_DATA帧类型
    frame = struct.pack('!BHI', frame_type, stream_id, max_stream_data)
    return frame

# ACK帧创建函数
def create_ack_frame(largest_acknowledged):
    return struct.pack('!BI', 0x02, largest_acknowledged)  # 0x02为ACK帧类型

# 发送ACK（接收端）
def send_ack(packet_number, addr, s, dest_conn_id, src_conn_id):
    try:
        # 模拟ACK丢失
        if random.random() < ACK_LOSS_PROBABILITY:
            print(f'ACK包编号{packet_number}丢失（模拟）')
        else:
            # 模拟网络延迟
            time.sleep(SIMULATED_NETWORK_DELAY)
            ack_frame = create_ack_frame(packet_number)
            header = create_quic_header(2, packet_number, dest_conn_id, src_conn_id)
            ack_packet = header + ack_frame
            s.sendto(ack_packet, addr)
            print(f'发送ACK，包编号: {packet_number}，目标地址: {addr}')
    except Exception as e:
        print(f'发送ACK时发生错误: {e}')

# 发送MAX_STREAM_DATA帧
def send_max_stream_data(stream_id, max_stream_data, addr, s, dest_conn_id, src_conn_id):
    try:
        # 模拟帧丢失
        if random.random() < ACK_LOSS_PROBABILITY:
            print(f'MAX_STREAM_DATA帧（流ID: {stream_id}）丢失（模拟）')
        else:
            # 模拟网络延迟
            time.sleep(SIMULATED_NETWORK_DELAY)
            max_stream_data_frame = create_max_stream_data_frame(stream_id, max_stream_data)
            header = create_quic_header(2, 0, dest_conn_id, src_conn_id)  # 使用0作为包编号
            control_packet = header + max_stream_data_frame
            s.sendto(control_packet, addr)
            print(f'发送MAX_STREAM_DATA帧，流ID: {stream_id}, 新的窗口大小: {max_stream_data}')
    except Exception as e:
        print(f'发送MAX_STREAM_DATA帧时发生错误: {e}')

# QUIC数据包头部创建函数
def create_quic_header(packet_type, packet_number, dest_conn_id, src_conn_id):
    dest_conn_id_len = len(dest_conn_id)
    src_conn_id_len = len(src_conn_id)
    header_format = f'!BIH{dest_conn_id_len}sH{src_conn_id_len}s'
    header = struct.pack(header_format, packet_type, packet_number, dest_conn_id_len, dest_conn_id,
                         src_conn_id_len, src_conn_id)
    return header

# 帧解析函数
def parse_frames(data):
    frames = []
    index = 0
    while index < len(data):
        frame_type = data[index]
        index += 1
        if frame_type == 0x08:  # STREAM帧
            # 回退一个字节，因为parse_stream_frame已经读取了frame_type
            index -= 1
            frame_data = data[index:]
            frame_type, stream_id, offset, payload = parse_stream_frame(frame_data)
            frames.append(('STREAM', stream_id, offset, payload))
            # 更新索引
            index += 9 + len(payload)
        elif frame_type == 0x02:  # ACK帧
            if len(data[index:]) < 4:
                print("ACK帧长度不足，无法解析")
                break
            ack_number = struct.unpack('!I', data[index:index + 4])[0]
            index += 4
            frames.append(('ACK', ack_number))
        elif frame_type == 0x11:  # MAX_STREAM_DATA帧
            if len(data[index:]) < 6:
                print("MAX_STREAM_DATA帧长度不足，无法解析")
                break
            stream_id, max_stream_data = struct.unpack('!HI', data[index:index + 6])
            index += 6
            frames.append(('MAX_STREAM_DATA', stream_id, max_stream_data))
        elif frame_type == 0x1c:  # CONNECTION_CLOSE帧
            if len(data[index:]) < 3:
                print("CONNECTION_CLOSE帧长度不足，无法解析")
                break
            error_code = struct.unpack('!H', data[index:index + 2])[0]
            index += 2
            reason_length = data[index]
            index += 1
            reason_phrase = data[index:index + reason_length]
            index += reason_length
            frames.append(('CONNECTION_CLOSE', error_code, reason_phrase))
        else:
            print(f"收到未知类型的帧，类型: {frame_type}")
            break
    return frames

# 主函数（接收端）
def main():
    state = ServerState.INITIAL  # 初始状态
    connections = {}  # conn_id: {'addr': addr, 'state': state, 'streams': {}, 'src_conn_id': bytes, 'dest_conn_id': bytes}

    # 初始化数据记录文件
    with open(receiver_log_file, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'stream_id', 'expected_offset', 'max_stream_data']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

    # 创建多个套接字，监听初始端口和迁移后的端口
    sockets = []
    bind_ports = [bind_port] + additional_ports
    for port in bind_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((bind_ip, port))
        s.settimeout(0.5)  # 设置超时时间
        sockets.append(s)
        print(f'服务器正在监听 {bind_ip}:{port}')

    server_conn_id = str(random.SystemRandom().randint(10000, 99999)).encode()

    while True:
        # 使用select监听多个套接字
        readable_sockets, _, _ = select.select(sockets, [], [], 1)
        if not readable_sockets:
            continue
        for s in readable_sockets:
            try:
                packet, addr = s.recvfrom(4096)
                server_port = s.getsockname()[1]  # 获取服务器的端口
            except socket.timeout:
                continue
            except Exception as e:
                print(f'接收数据时发生错误: {e}')
                continue
            print(f'服务器端口: {server_port}, 收到来自 {addr} 的数据包')
            # 模拟数据包丢失
            if random.random() < DATA_LOSS_PROBABILITY:
                print(f'来自{addr}的数据包丢失（模拟）')
                continue
            # 模拟网络延迟
            time.sleep(SIMULATED_NETWORK_DELAY)
            try:
                packet_type, packet_number, dest_conn_id, src_conn_id, payload = parse_quic_header(packet)
            except Exception as e:
                print(f'解析数据包时发生错误: {e}')
                continue
            # 使用源连接ID来识别连接
            client_conn_id = src_conn_id.decode()
            if client_conn_id not in connections:
                connections[client_conn_id] = {
                    'addr': addr,
                    'state': ServerState.INITIAL,
                    'streams': {},
                    'src_conn_id': src_conn_id,
                    'dest_conn_id': server_conn_id
                }
                print(f'新连接，客户端连接ID: {client_conn_id}, 来自地址: {addr}')
            else:
                # 更新地址以支持连接迁移
                if connections[client_conn_id]['addr'] != addr:
                    print(f'检测到连接迁移，客户端连接ID: {client_conn_id}, 旧地址: {connections[client_conn_id]["addr"]}, 新地址: {addr}')
                    connections[client_conn_id]['addr'] = addr
            conn_state = connections[client_conn_id]['state']
            streams = connections[client_conn_id]['streams']
            conn_src_conn_id = connections[client_conn_id]['src_conn_id']
            conn_dest_conn_id = connections[client_conn_id]['dest_conn_id']
            if conn_state == ServerState.INITIAL and packet_type == 0:  # 初始数据包（Client Hello）
                print(f'收到初始数据包，客户端连接ID: {client_conn_id}, 类型={packet_type}, 编号={packet_number}, 负载={payload.decode()}')
                response_packet_type = 1  # 响应数据包类型
                response_header = create_quic_header(response_packet_type, packet_number, conn_src_conn_id, conn_dest_conn_id)
                response_data = b'Server Hello'
                response_packet = response_header + response_data
                # 模拟网络延迟
                time.sleep(SIMULATED_NETWORK_DELAY)
                try:
                    s.sendto(response_packet, addr)
                    print(f'发送服务器Hello: 包编号: {packet_number}, 目标连接ID: {conn_src_conn_id.decode()}, 源连接ID: {conn_dest_conn_id.decode()}')
                except Exception as e:
                    print(f'发送服务器Hello时发生错误: {e}')
                    continue
                connections[client_conn_id]['state'] = ServerState.HANDSHAKE  # 进入握手状态
            elif conn_state == ServerState.HANDSHAKE and packet_type == 1:  # 握手完成
                print(f'收到握手完成数据包，客户端连接ID: {client_conn_id}, 类型={packet_type}, 编号={packet_number}, 负载={payload.decode()}')
                # 发送握手完成包的ACK
                send_ack(packet_number, addr, s, conn_src_conn_id, conn_dest_conn_id)
                connections[client_conn_id]['state'] = ServerState.CONNECTED  # 进入已连接状态
            elif conn_state == ServerState.CONNECTED and packet_type == 2:  # 数据包
                try:
                    frames = parse_frames(payload)
                    for frame in frames:
                        if frame[0] == 'STREAM':
                            stream_id = frame[1]
                            offset = frame[2]
                            stream_payload = frame[3]
                            print(f'收到数据包: 编号={packet_number}, 流ID={stream_id}, 偏移量={offset}, 长度={len(stream_payload)}，客户端连接ID: {client_conn_id}')
                            # 初始化流的接收状态
                            if stream_id not in streams:
                                streams[stream_id] = {
                                    'received_data': {},
                                    'expected_offset': 0,
                                    'max_stream_data': 500  # 初始窗口大小
                                }
                            stream = streams[stream_id]
                            # 存储按偏移量的数据
                            if offset not in stream['received_data']:
                                stream['received_data'][offset] = stream_payload
                                # 更新流量控制窗口
                                stream['max_stream_data'] += len(stream_payload)
                                # 发送MAX_STREAM_DATA帧，告知发送方窗口已更新
                                send_max_stream_data(stream_id, stream['max_stream_data'], addr, s, conn_src_conn_id, conn_dest_conn_id)
                                # 记录接收的数据
                                with open(receiver_log_file, 'a', newline='') as csvfile:
                                    writer = csv.DictWriter(csvfile, fieldnames=['timestamp', 'stream_id', 'expected_offset', 'max_stream_data'])
                                    writer.writerow({
                                        'timestamp': time.time(),
                                        'stream_id': stream_id,
                                        'expected_offset': stream['expected_offset'],
                                        'max_stream_data': stream['max_stream_data']
                                    })
                            # 无论是否是重复数据包，都发送ACK
                            send_ack(packet_number, addr, s, conn_src_conn_id, conn_dest_conn_id)
                            # 尝试按顺序组装数据
                            while stream['expected_offset'] in stream['received_data']:
                                data = stream['received_data'][stream['expected_offset']]
                                # 处理数据（例如，写入文件或缓冲区）
                                print(f'处理数据，流ID={stream_id}, 偏移量={stream["expected_offset"]}, 长度={len(data)}')
                                del stream['received_data'][stream['expected_offset']]
                                stream['expected_offset'] += len(data)
                        elif frame[0] == 'CONNECTION_CLOSE':
                            error_code = frame[1]
                            reason_phrase = frame[2].decode()
                            print(f'收到 CONNECTION_CLOSE 帧，错误码: {error_code}, 原因: {reason_phrase}')
                            # 更新连接状态
                            connections[client_conn_id]['state'] = ServerState.CLOSED
                            # 释放连接相关的资源
                            del connections[client_conn_id]
                            print(f'连接 {client_conn_id} 已关闭')
                        else:
                            print(f'收到未知类型的帧，类型: {frame[0]}')
                except Exception as e:
                    print(f'处理数据包时发生错误: {e}')
                    continue
            elif conn_state == ServerState.CLOSED:
                print(f'连接 {client_conn_id} 已关闭，忽略收到的数据包')
            else:
                print(f'收到未知状态下的数据包，丢弃。客户端连接ID: {client_conn_id}, 状态: {conn_state}')

        # 可选地检查所有连接是否已关闭
        if not connections:
            print('所有连接已关闭，服务器停止监听')
            break  # 退出主循环，服务器停止运行

    # 关闭所有套接字
    for s in sockets:
        s.close()

if __name__ == '__main__':
    main()
