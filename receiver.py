# Receiver (receiver.py) with Improved Error Handling and Reduced Loss Probability
import socket
import struct
import random
import time
import csv  # 用于数据记录
from enum import Enum

# 定义服务器状态
class ServerState(Enum):
    INITIAL = 1
    HANDSHAKE = 2
    CONNECTED = 3
    CLOSED = 4

# 常量
bind_ip = '172.20.0.3'
bind_port = 12346
DATA_LOSS_PROBABILITY = 0.0  # 数据包丢失概率，暂时设为0
ACK_LOSS_PROBABILITY = 0.0  # ACK 丢失概率，暂时设为0

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
    frame_type = 0x11  # MAX_STREAM_DATA帧类型（示例值）
    frame = struct.pack('!BHI', frame_type, stream_id, max_stream_data)
    return frame

# ACK帧创建函数
def create_ack_frame(largest_acknowledged):
    return struct.pack('!BI', 0x02, largest_acknowledged)  # 0x02为示例ACK帧类型

# 发送ACK（接收端）
def send_ack(packet_number, addr, s):
    try:
        # 模拟ACK丢失
        if random.random() < ACK_LOSS_PROBABILITY:
            print(f'ACK包编号{packet_number}丢失（模拟）')
            return
        # 模拟网络延迟
        time.sleep(SIMULATED_NETWORK_DELAY)
        ack_frame = create_ack_frame(packet_number)
        s.sendto(ack_frame, addr)
        print(f'发送ACK，包编号: {packet_number}，目标地址: {addr}')
    except Exception as e:
        print(f'发送ACK时发生错误: {e}')

# 发送MAX_STREAM_DATA帧
def send_max_stream_data(stream_id, max_stream_data, addr, s):
    try:
        # 模拟帧丢失
        if random.random() < ACK_LOSS_PROBABILITY:
            print(f'MAX_STREAM_DATA帧（流ID: {stream_id}）丢失（模拟）')
            return
        # 模拟网络延迟
        time.sleep(SIMULATED_NETWORK_DELAY)
        max_stream_data_frame = create_max_stream_data_frame(stream_id, max_stream_data)
        s.sendto(max_stream_data_frame, addr)
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

# 主函数（接收端）
def main():
    state = ServerState.INITIAL  # 初始状态
    connections = {}  # conn_id: {'addr': addr, 'state': state, 'streams': {}}

    # 初始化数据记录文件
    with open(receiver_log_file, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'stream_id', 'expected_offset', 'max_stream_data']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((bind_ip, bind_port))
        s.settimeout(0.5)  # 增加超时时间，防止因延迟导致的超时
        server_conn_id = str(random.SystemRandom().randint(10000, 99999)).encode()

        while True:
            try:
                packet, addr = s.recvfrom(4096)
            except socket.timeout:
                continue
            except Exception as e:
                print(f'接收数据时发生错误: {e}')
                continue

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

            # 只处理发送给本服务器的连接ID的数据包
            if dest_conn_id != server_conn_id and dest_conn_id != b'':
                print(f'收到未知连接ID的数据包，忽略。连接ID: {dest_conn_id.decode()}')
                continue

            # 根据源连接ID识别连接
            client_conn_id = src_conn_id.decode()
            if client_conn_id not in connections:
                connections[client_conn_id] = {'addr': addr, 'state': ServerState.INITIAL, 'streams': {}}
                print(f'新连接，客户端连接ID: {client_conn_id}, 来自地址: {addr}')
            else:
                # 更新地址以支持连接迁移
                if connections[client_conn_id]['addr'] != addr:
                    print(f'检测到连接迁移，客户端连接ID: {client_conn_id}, 新地址: {addr}')
                    connections[client_conn_id]['addr'] = addr

            conn_state = connections[client_conn_id]['state']
            streams = connections[client_conn_id]['streams']

            if conn_state == ServerState.INITIAL and packet_type == 0:  # 初始数据包（Client Hello）
                print(f'收到初始数据包，客户端连接ID: {client_conn_id}, 类型={packet_type}, 编号={packet_number}, 负载={payload.decode()}')
                response_packet_type = 1  # 响应数据包类型
                response_header = create_quic_header(response_packet_type, packet_number, src_conn_id, server_conn_id)
                response_data = b'Server Hello'
                response_packet = response_header + response_data
                # 模拟网络延迟
                time.sleep(SIMULATED_NETWORK_DELAY)
                try:
                    s.sendto(response_packet, addr)
                    print(f'发送服务器Hello: 包编号: {packet_number}, 目标连接ID: {src_conn_id.decode()}, 源连接ID: {server_conn_id.decode()}')
                except Exception as e:
                    print(f'发送服务器Hello时发生错误: {e}')
                    continue
                connections[client_conn_id]['state'] = ServerState.HANDSHAKE  # 进入握手状态

            elif conn_state == ServerState.HANDSHAKE and packet_type == 1:  # 握手完成
                print(f'收到握手完成数据包，客户端连接ID: {client_conn_id}, 类型={packet_type}, 编号={packet_number}, 负载={payload.decode()}')
                # 发送握手完成包的ACK
                send_ack(packet_number, addr, s)
                connections[client_conn_id]['state'] = ServerState.CONNECTED  # 进入已连接状态

            elif conn_state == ServerState.CONNECTED and packet_type == 2:  # 数据包
                try:
                    frame_type = payload[0]
                    if frame_type == 0x08:  # STREAM帧
                        _, stream_id, offset, stream_payload = parse_stream_frame(payload)
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
                            send_max_stream_data(stream_id, stream['max_stream_data'], addr, s)

                            # 记录接收的数据
                            with open(receiver_log_file, 'a', newline='') as csvfile:
                                writer = csv.DictWriter(csvfile, fieldnames=['timestamp', 'stream_id', 'expected_offset', 'max_stream_data'])
                                writer.writerow({
                                    'timestamp': time.time(),
                                    'stream_id': stream_id,
                                    'expected_offset': stream['expected_offset'],
                                    'max_stream_data': stream['max_stream_data']
                                })
                        send_ack(packet_number, addr, s)
                    else:
                        print(f'收到未知类型的帧，类型: {frame_type}')
                except ValueError as e:
                    print(f'解析包编号{packet_number}时出错: {e}')
                    continue
                except Exception as e:
                    print(f'处理数据包时发生错误: {e}')
                    continue

                # 尝试按顺序组装数据
                stream = streams[stream_id]
                while stream['expected_offset'] in stream['received_data']:
                    data = stream['received_data'][stream['expected_offset']]
                    # 处理数据（例如，写入文件或缓冲区）
                    print(f'处理数据，流ID={stream_id}, 偏移量={stream["expected_offset"]}, 长度={len(data)}')
                    del stream['received_data'][stream['expected_offset']]
                    stream['expected_offset'] += len(data)

    s.close()

if __name__ == '__main__':
        main()
