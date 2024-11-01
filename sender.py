# Sender (sender.py) with BBR Congestion Control, Error Handling, and Congestion Window Monitoring
import socket
import struct
import time
import os
import random
import csv  # 用于数据记录
from enum import Enum

# 定义客户端状态
class ClientState(Enum):
    INITIAL = 1
    HANDSHAKE = 2
    CONNECTED = 3
    MIGRATED = 4
    CLOSED = 5

# 常量
dest_ip = '172.20.0.3'
dest_port = 12346
RTO = 1.0  # 重传超时时间（秒）
WINDOW_SIZE = 5  # 发送窗口大小
NUM_STREAMS = 3  # 并发的流数量

# 数据记录文件
sender_log_file = 'sender_log.csv'  # 用于记录发送的数据包信息
metrics_log_file = 'metrics_log.csv'  # 用于记录拥塞控制的指标

# QUIC数据包头部创建函数
def create_quic_header(packet_type, packet_number, dest_conn_id, src_conn_id):
    dest_conn_id_len = len(dest_conn_id)
    src_conn_id_len = len(src_conn_id)
    header_format = f'!BIH{dest_conn_id_len}sH{src_conn_id_len}s'
    header = struct.pack(header_format, packet_type, packet_number, dest_conn_id_len, dest_conn_id,
                         src_conn_id_len, src_conn_id)
    return header

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
    index +=2
    src_conn_id = data[index:index + src_conn_id_len]
    index += src_conn_id_len
    header_size = index
    return packet_type, packet_number, dest_conn_id, src_conn_id, header_size

# STREAM帧创建函数
def create_stream_frame(stream_id, offset, data):
    payload_length = len(data)
    frame_type = 0x08  # STREAM帧类型
    frame_format = f'!BHIH{payload_length}s'
    frame = struct.pack(frame_format, frame_type, stream_id, offset, payload_length, data)
    return frame

# MAX_STREAM_DATA帧创建函数
def create_max_stream_data_frame(stream_id, max_stream_data):
    frame_type = 0x11  # MAX_STREAM_DATA帧类型（示例值）
    frame = struct.pack('!BHI', frame_type, stream_id, max_stream_data)
    return frame

# 发送初始数据包（客户端Hello）
def send_initial_packet(s, packet_number, source_conn_id):
    initial_packet_type = 0  # 初始数据包类型
    dest_conn_id = b''  # 初始包没有目标连接ID
    initial_header = create_quic_header(initial_packet_type, packet_number, dest_conn_id, source_conn_id)
    initial_data = b'Client Hello'
    initial_packet = initial_header + initial_data
    s.sendto(initial_packet, (dest_ip, dest_port))
    print(f'发送初始数据包: 包编号: {packet_number}, 源连接ID: {source_conn_id.decode()}')
    return initial_packet  # 返回数据包内容

# 发送握手完成数据包（客户端确认）
def send_handshake_completion(s, packet_number, dest_conn_id, source_conn_id):
    handshake_packet_type = 1  # 握手完成数据包类型
    handshake_header = create_quic_header(handshake_packet_type, packet_number, dest_conn_id, source_conn_id)
    handshake_data = b'Client Handshake Completion'
    handshake_packet = handshake_header + handshake_data
    s.sendto(handshake_packet, (dest_ip, dest_port))
    print(f'发送握手完成数据包: 包编号: {packet_number}, 目标连接ID: {dest_conn_id.decode()}, 源连接ID: {source_conn_id.decode()}')
    return handshake_packet  # 返回数据包内容

# 主函数（发送端）
def main():
    packet_number = 1  # 初始化包编号
    source_conn_id = str(random.SystemRandom().randint(10000, 99999)).encode()
    state = ClientState.INITIAL  # 初始状态

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)  # 非阻塞模式，超时时间短

    pending_acks = {}  # packet_number: (timestamp, packet)
    streams = {}  # stream_id: {'offset': int, 'data_packets_sent': int, 'max_stream_data': int}

    initial_max_stream_data = 500  # 初始流量控制窗口大小

    # BBR参数
    btlbw = None  # 瓶颈带宽估计值，初始为None
    min_rtt = None  # 最小RTT，初始为None
    pacing_rate = 1e6  # 初始发送速率（字节/秒）
    bbr_state = 'startup'  # BBR状态机
    send_quantum = 1200  # 每个数据包的大小（字节）
    last_send_time = 0  # 上次发送的时间

    # 初始化数据记录文件
    with open(sender_log_file, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'stream_id', 'offset', 'max_stream_data']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

    # 初始化指标记录文件
    with open(metrics_log_file, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'packet_number', 'rtt', 'btlbw', 'pacing_rate', 'bbr_state', 'pending_acks', 'cwnd']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

    # 初始化拥塞窗口大小（cwnd），这里使用pending_acks的数量作为近似
    cwnd = WINDOW_SIZE  # 初始拥塞窗口大小

    for i in range(NUM_STREAMS):
        stream_id = i  # 简单地将流ID设为0,1,2,...
        streams[stream_id] = {
            'offset': 0,
            'data_packets_sent': 0,
            'max_stream_data': initial_max_stream_data,  # 初始窗口大小
            'blocked': False  # 是否被流量控制阻塞
        }

    total_packets_per_stream = 10  # 每个流要发送的数据包数
    data_length = 50  # 每个数据包的数据大小
    total_packets = total_packets_per_stream * NUM_STREAMS

    dest_conn_id = b''  # 初始化dest_conn_id为空

    migration_triggered = False  # 是否触发了连接迁移

    stream_ids = list(streams.keys())
    stream_index = 0  # Index to cycle through streams

    while state != ClientState.CLOSED:
        if state == ClientState.INITIAL:
            # 步骤1：发送初始数据包 - Client Hello
            initial_packet = send_initial_packet(s, packet_number, source_conn_id)
            pending_acks[packet_number] = (time.time(), initial_packet)
            packet_number += 1
            state = ClientState.HANDSHAKE  # 进入握手状态

        elif state == ClientState.HANDSHAKE:
            # 等待服务器响应
            try:
                response, addr = s.recvfrom(4096)
                # 解析响应
                packet_type, recv_packet_number, dest_conn_id_recv, src_conn_id_recv, header_size = parse_quic_header(response)
                payload = response[header_size:]
                if packet_type == 1:  # 收到服务器Hello
                    print(f'收到来自{addr}的响应: 类型={packet_type}, 编号={recv_packet_number}, 目标连接ID={dest_conn_id_recv.decode()}, 源连接ID={src_conn_id_recv.decode()}, 负载={payload.decode()}')
                    if recv_packet_number in pending_acks:
                        del pending_acks[recv_packet_number]
                    dest_conn_id = src_conn_id_recv  # 更新服务器的连接ID
                    state = ClientState.CONNECTED  # 进入已连接状态
            except socket.timeout:
                # 检查是否需要重传
                current_time = time.time()
                for pkt_num, (timestamp, packet) in list(pending_acks.items()):
                    if current_time - timestamp > RTO:
                        print(f'包编号{pkt_num}超时，正在重传...')
                        s.sendto(packet, (dest_ip, dest_port))
                        pending_acks[pkt_num] = (current_time, packet)
                        print(f'已重传包编号: {pkt_num}')
            except Exception as e:
                print(f'接收服务器响应时发生错误: {e}')

        elif state == ClientState.CONNECTED:
            # 步骤2：发送握手完成数据包 - 客户端确认
            handshake_packet = send_handshake_completion(s, packet_number, dest_conn_id, source_conn_id)
            pending_acks[packet_number] = (time.time(), handshake_packet)
            packet_number += 1

            sent_all_packets = False

            while not sent_all_packets or pending_acks:
                # 模拟连接迁移（在发送一半数据后）
                total_data_packets_sent = sum([streams[sid]['data_packets_sent'] for sid in streams])

                if not migration_triggered and total_data_packets_sent >= total_packets // 2:
                    print('正在模拟连接迁移...')
                    # 不关闭旧的套接字，直接创建新套接字
                    old_s = s  # 保存旧的套接字
                    new_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    new_s.settimeout(0.5)
                    s = new_s  # 更新套接字引用
                    old_s.close()  # 关闭旧的套接字
                    migration_triggered = True
                    print('连接迁移完成，继续发送数据...')

                # 接收ACK、MAX_STREAM_DATA并处理超时重传
                try:
                    ack_response, _ = s.recvfrom(1024)
                    ack_type = ack_response[0]
                    if ack_type == 0x02:  # ACK帧
                        ack_number = struct.unpack('!I', ack_response[1:5])[0]
                        if ack_number in pending_acks:
                            send_time = pending_acks[ack_number][0]
                            rtt = time.time() - send_time
                            if rtt == 0:
                                rtt = 0.000001  # 避免除以零
                            # 模拟实际网络延迟，忽略过小的RTT
                            if rtt < 0.01:
                                rtt = 0.01
                            # 初始化min_rtt和btlbw
                            if min_rtt is None or rtt < min_rtt:
                                min_rtt = rtt
                            print(f'收到ACK，包编号: {ack_number}, RTT: {rtt:.6f}s')
                            # 更新带宽估计
                            inst_bw = send_quantum / rtt
                            if btlbw is None or inst_bw > btlbw:
                                btlbw = inst_bw
                            del pending_acks[ack_number]
                            # 更新拥塞窗口大小（这里简单地使用pending_acks的数量）
                            cwnd = max(cwnd, len(pending_acks))

                            # 根据BBR状态机调整速率
                            if bbr_state == 'startup':
                                pacing_rate = btlbw * 2  # 在启动阶段，加倍发送速率
                                if btlbw >= pacing_rate / 2:
                                    bbr_state = 'drain'
                                    print('进入Drain状态')
                            elif bbr_state == 'drain':
                                pacing_rate = btlbw
                                if len(pending_acks) <= WINDOW_SIZE / 2:
                                    bbr_state = 'probe_bw'
                                    print('进入ProbeBW状态')
                            elif bbr_state == 'probe_bw':
                                pacing_rate = btlbw

                            # 记录指标
                            with open(metrics_log_file, 'a', newline='') as csvfile:
                                writer = csv.DictWriter(csvfile, fieldnames=['timestamp', 'packet_number', 'rtt', 'btlbw', 'pacing_rate', 'bbr_state', 'pending_acks', 'cwnd'])
                                writer.writerow({
                                    'timestamp': time.time(),
                                    'packet_number': ack_number,
                                    'rtt': rtt,
                                    'btlbw': btlbw,
                                    'pacing_rate': pacing_rate,
                                    'bbr_state': bbr_state,
                                    'pending_acks': len(pending_acks),
                                    'cwnd': cwnd
                                })

                    elif ack_type == 0x11:  # MAX_STREAM_DATA帧
                        stream_id, max_stream_data = struct.unpack('!HI', ack_response[1:7])
                        if stream_id in streams:
                            streams[stream_id]['max_stream_data'] = max_stream_data
                            streams[stream_id]['blocked'] = False
                            print(f'收到MAX_STREAM_DATA，流ID: {stream_id}, 新的窗口大小: {max_stream_data}')
                except socket.timeout:
                    pass
                except Exception as e:
                    print(f'接收ACK时发生错误: {e}')
                    break

                # 检查超时并重传
                current_time = time.time()
                for pkt_num, (timestamp, packet) in list(pending_acks.items()):
                    if current_time - timestamp > RTO:
                        print(f'包编号{pkt_num}超时，作为新包重传...')
                        # 重传数据包，使用新的包编号
                        packet_type, _, dest_conn_id_packet, src_conn_id_packet, header_size = parse_quic_header(packet)
                        payload = packet[header_size:]
                        header = create_quic_header(packet_type, packet_number, dest_conn_id_packet, src_conn_id_packet)
                        new_packet = header + payload
                        s.sendto(new_packet, (dest_ip, dest_port))
                        print(f'已重传包编号: {packet_number}')
                        pending_acks[packet_number] = (current_time, new_packet)
                        packet_number += 1  # 递增包编号
                        del pending_acks[pkt_num]

                # 计算 pacing_interval
                if btlbw is not None:
                    pacing_interval = send_quantum / pacing_rate
                    elapsed = time.time() - last_send_time
                    if elapsed < pacing_interval:
                        # 等待下一个发送时间
                        time.sleep(pacing_interval - elapsed)
                else:
                    # 如果尚未计算btlbw，使用默认间隔
                    pacing_interval = 0

                # 发送数据包（遵循流量控制和BBR速率控制）
                if len(pending_acks) < cwnd and not sent_all_packets:
                    # 获取当前的流ID
                    stream_id = stream_ids[stream_index % len(stream_ids)]
                    stream = streams[stream_id]
                    # 检查流量控制窗口
                    if stream['blocked']:
                        print(f'流ID {stream_id} 被流量控制阻塞，等待窗口更新')
                    elif stream['data_packets_sent'] < total_packets_per_stream:
                        # 计算将要发送的数据大小
                        data = os.urandom(data_length)
                        new_offset = stream['offset'] + len(data)
                        if new_offset > stream['max_stream_data']:
                            # 超过流量控制窗口，发送 BLOCKED 帧（这里简化处理）
                            stream['blocked'] = True
                            print(f'流ID {stream_id} 达到流量控制窗口，暂停发送')
                        else:
                            header = create_quic_header(2, packet_number, dest_conn_id, source_conn_id)
                            stream_frame = create_stream_frame(stream_id, stream['offset'], data)
                            packet = header + stream_frame
                            s.sendto(packet, (dest_ip, dest_port))
                            print(f'发送数据包编号: {packet_number}, 流ID: {stream_id}, 偏移量: {stream["offset"]}')
                            pending_acks[packet_number] = (time.time(), packet)
                            packet_number += 1  # 递增包编号
                            stream['offset'] += len(data)
                            stream['data_packets_sent'] += 1  # 递增已发送数据包计数
                            last_send_time = time.time()

                            # 记录发送的数据
                            with open(sender_log_file, 'a', newline='') as csvfile:
                                writer = csv.DictWriter(csvfile, fieldnames=['timestamp', 'stream_id', 'offset', 'max_stream_data'])
                                writer.writerow({
                                    'timestamp': time.time(),
                                    'stream_id': stream_id,
                                    'offset': stream['offset'],
                                    'max_stream_data': stream['max_stream_data']
                                })
                    else:
                        # 该流的数据已发送完毕
                        pass
                    # 移动到下一个流
                    stream_index += 1
                    # 检查是否所有数据包都已发送
                    total_data_packets_sent = sum([streams[sid]['data_packets_sent'] for sid in streams])
                    if total_data_packets_sent >= total_packets:
                        sent_all_packets = True

                # 如果所有流都被阻塞，等待窗口更新
                all_blocked = all([streams[sid]['blocked'] or streams[sid]['data_packets_sent'] >= total_packets_per_stream for sid in streams])
                if all_blocked and not sent_all_packets:
                    print('所有流都被流量控制阻塞，等待窗口更新')
                    time.sleep(0.1)  # 等待一段时间

            if state != ClientState.MIGRATED:
                print('所有数据包已发送并被确认。')
                state = ClientState.CLOSED

        elif state == ClientState.MIGRATED:
            # 继续发送剩余的数据包
            print('连接迁移完成，继续发送数据...')
            state = ClientState.CONNECTED  # 返回已连接状态

    s.close()

if __name__ == '__main__':
    main()
