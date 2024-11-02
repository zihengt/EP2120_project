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
new_dest_ip = '172.20.0.3'  # 新的目标IP地址
new_dest_port = 12347       # 新的目标端口

INITIAL_RTO = 1.0  # 初始重传超时时间（秒）
MIN_RTO = 1.0      # 最小 RTO
MAX_RTO = 60.0     # 最大 RTO
NUM_STREAMS = 3    # 并发的流数量

# 数据记录文件
sender_log_file = 'sender_log.csv'    # 用于记录发送的数据包信息
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
    index += 2
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
    frame_type = 0x11  # MAX_STREAM_DATA帧类型
    frame = struct.pack('!BHI', frame_type, stream_id, max_stream_data)
    return frame

# 通用帧解析函数
def parse_frames(data):
    frames = []
    index = 0
    while index < len(data):
        frame_type = data[index]
        index += 1
        if frame_type == 0x02:  # ACK帧
            if len(data[index:]) < 4:
                print("ACK帧长度不足，无法解析")
                break
            ack_number = struct.unpack('!I', data[index:index+4])[0]
            index += 4
            frames.append(('ACK', ack_number))
        elif frame_type == 0x11:  # MAX_STREAM_DATA帧
            if len(data[index:]) < 6:
                print("MAX_STREAM_DATA帧长度不足，无法解析")
                break
            stream_id, max_stream_data = struct.unpack('!HI', data[index:index+6])
            index += 6
            frames.append(('MAX_STREAM_DATA', stream_id, max_stream_data))
        else:
            print(f"收到未知类型的帧，类型: {frame_type}")
            break
    return frames

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
    global dest_ip, dest_port  # 声明为全局变量，以便在函数内部修改

    packet_number = 1  # 初始化包编号
    source_conn_id = str(random.SystemRandom().randint(10000, 99999)).encode()
    state = ClientState.INITIAL  # 初始状态

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)  # 非阻塞模式，超时时间短

    pending_acks = {}  # packet_number: {'timestamp': timestamp, 'packet': packet, 'retransmit_count': count, 'retransmitted': bool}
    streams = {}  # stream_id: {'offset': int, 'data_packets_sent': int, 'max_stream_data': int, 'blocked': bool}

    initial_max_stream_data = 500  # 初始流量控制窗口大小

    # 拥塞控制参数
    data_length = 50  # 每个数据包的数据大小（字节）
    header_length = 1 + 4 + 2 + len(source_conn_id) + 2 + len(source_conn_id)  # 根据连接ID长度计算包头长度
    stream_frame_header_length = 1 + 2 + 4 + 2  # STREAM帧头部长度
    MSS = data_length + header_length + stream_frame_header_length  # 实际数据包大小（字节）
    cwnd = MSS  # 拥塞窗口，单位为字节
    ssthresh = 600  # 慢启动阈值
    MAX_CWND = 1000000  # 设置一个合理的最大拥塞窗口值
    dup_ack_count = 0  # 重复ACK计数器

    # 新增变量
    acknowledged_packets = set()  # 已确认的包编号集合

    # RTO 相关参数
    SRTT = None  # 平滑的 RTT
    RTTVAR = None  # RTT 的方差
    RTO = INITIAL_RTO  # 重传超时时间
    alpha = 1/8
    beta = 1/4

    MAX_RETRANSMIT = 5  # 最大重传次数

    # 初始化数据记录文件
    with open(sender_log_file, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'stream_id', 'offset', 'max_stream_data']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

    # 初始化指标记录文件
    with open(metrics_log_file, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'packet_number', 'rtt', 'srtt', 'rttvar', 'rto', 'cwnd', 'ssthresh', 'state', 'inflight_packets']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

    for i in range(NUM_STREAMS):
        stream_id = i  # 简单地将流ID设为0,1,2,...
        streams[stream_id] = {
            'offset': 0,
            'data_packets_sent': 0,
            'max_stream_data': initial_max_stream_data,  # 初始窗口大小
            'blocked': False  # 是否被流量控制阻塞
        }

    total_packets_per_stream = 20  # 每个流要发送的数据包数
    total_packets = total_packets_per_stream * NUM_STREAMS

    dest_conn_id = b''  # 初始化dest_conn_id为空

    migration_triggered = False  # 是否触发了连接迁移

    stream_ids = list(streams.keys())
    stream_index = 0  # Index to cycle through streams

    while state != ClientState.CLOSED:
        if state == ClientState.INITIAL:
            # 步骤1：发送初始数据包 - Client Hello
            initial_packet = send_initial_packet(s, packet_number, source_conn_id)
            pending_acks[packet_number] = {
                'timestamp': time.time(),
                'packet': initial_packet,
                'retransmit_count': 0,
                'retransmitted': False
            }
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
                for pkt_num, pkt_info in list(pending_acks.items()):
                    if current_time - pkt_info['timestamp'] > RTO:
                        if pkt_info['retransmit_count'] >= MAX_RETRANSMIT:
                            print(f'包编号{pkt_num}重传次数超过上限，放弃重传')
                            del pending_acks[pkt_num]
                            continue
                        print(f'包编号{pkt_num}超时，正在重传...')
                        s.sendto(pkt_info['packet'], (dest_ip, dest_port))
                        pkt_info['timestamp'] = current_time
                        pkt_info['retransmit_count'] += 1
                        pkt_info['retransmitted'] = True
                        print(f'已重传包编号: {pkt_num}')
                        # 加倍 RTO
                        RTO = min(RTO * 2, MAX_RTO)
            except Exception as e:
                print(f'接收服务器响应时发生错误: {e}')

        elif state == ClientState.CONNECTED:
            # 步骤2：发送握手完成数据包 - 客户端确认
            handshake_packet = send_handshake_completion(s, packet_number, dest_conn_id, source_conn_id)
            pending_acks[packet_number] = {
                'timestamp': time.time(),
                'packet': handshake_packet,
                'retransmit_count': 0,
                'retransmitted': False
            }
            packet_number += 1

            sent_all_packets = False

            while not sent_all_packets or pending_acks:
                # 模拟连接迁移（在发送一半数据后）
                total_data_packets_sent = sum([streams[sid]['data_packets_sent'] for sid in streams])

                if not migration_triggered and total_data_packets_sent >= total_packets // 2:
                    print('正在模拟连接迁移...')
                    # **更新目标IP和端口，并创建新的套接字**
                    s.close()
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.settimeout(0.5)
                    # 可选地绑定到新的源地址和端口
                    # s.bind(('127.0.0.1', 0))  # 绑定到随机端口
                    dest_ip = new_dest_ip
                    dest_port = new_dest_port
                    migration_triggered = True
                    print(f'连接迁移完成，新的目标IP: {dest_ip}, 端口: {dest_port}')

                # 接收ACK、MAX_STREAM_DATA并处理超时重传
                try:
                    ack_response, _ = s.recvfrom(1024)
                    # 解析 QUIC 包头
                    packet_type, recv_packet_number, dest_conn_id_recv, src_conn_id_recv, header_size = parse_quic_header(ack_response)
                    payload = ack_response[header_size:]  # 提取有效负载（帧）
                    frames = parse_frames(payload)
                    for frame in frames:
                        if frame[0] == 'ACK':
                            ack_number = frame[1]
                            print(f'收到ACK，包编号: {ack_number}')
                            if ack_number not in acknowledged_packets:
                                acknowledged_packets.add(ack_number)
                                if ack_number in pending_acks:
                                    pkt_info = pending_acks[ack_number]
                                    send_time = pkt_info['timestamp']
                                    if not pkt_info['retransmitted']:
                                        # 仅使用未重传的数据包的RTT样本
                                        rtt_sample = time.time() - send_time
                                        if rtt_sample == 0:
                                            rtt_sample = 0.000001  # 避免除以零
                                        # 初始化 SRTT 和 RTTVAR
                                        if SRTT is None:
                                            SRTT = rtt_sample
                                            RTTVAR = rtt_sample / 2
                                        else:
                                            RTTVAR = (1 - beta) * RTTVAR + beta * abs(SRTT - rtt_sample)
                                            SRTT = (1 - alpha) * SRTT + alpha * rtt_sample
                                        RTO = max(SRTT + 4 * RTTVAR, MIN_RTO)
                                        print(f'RTT: {rtt_sample:.6f}s, SRTT: {SRTT:.6f}s, RTTVAR: {RTTVAR:.6f}s, RTO: {RTO:.6f}s')
                                    else:
                                        print(f'包编号 {ack_number} 是重传包的ACK，不更新RTT估计')
                                    del pending_acks[ack_number]
                                    acked_packets = 1  # 每个ACK确认一个数据包

                                    # 更新拥塞窗口
                                    if cwnd < ssthresh:
                                        # 慢启动阶段
                                        cwnd += MSS * acked_packets
                                    else:
                                        # 拥塞避免阶段
                                        cwnd += (MSS * MSS / cwnd) * acked_packets
                                    cwnd = min(cwnd, MAX_CWND)
                                    dup_ack_count = 0  # 重置重复ACK计数器
                                else:
                                    print(f'ACK 包编号 {ack_number} 未在待确认列表中')
                        elif frame[0] == 'MAX_STREAM_DATA':
                            stream_id, max_stream_data = frame[1], frame[2]
                            if stream_id in streams:
                                streams[stream_id]['max_stream_data'] = max_stream_data
                                streams[stream_id]['blocked'] = False
                                print(f'收到MAX_STREAM_DATA，流ID: {stream_id}, 新的窗口大小: {max_stream_data}')
                            else:
                                print(f'收到未知流的MAX_STREAM_DATA，流ID: {stream_id}')
                        else:
                            print(f'收到未知类型的帧，类型: {frame[0]}')
                except socket.timeout:
                    pass
                except Exception as e:
                    print(f'接收ACK时发生错误: {e}')
                    break

                # 检查超时并重传
                current_time = time.time()
                for pkt_num, pkt_info in list(pending_acks.items()):
                    if current_time - pkt_info['timestamp'] > RTO:
                        if pkt_info['retransmit_count'] >= MAX_RETRANSMIT:
                            print(f'包编号{pkt_num}重传次数超过上限，放弃重传')
                            del pending_acks[pkt_num]
                            continue
                        print(f'包编号{pkt_num}超时（RTO={RTO:.6f}s），重传并调整拥塞窗口...')
                        # 重传数据包
                        s.sendto(pkt_info['packet'], (dest_ip, dest_port))
                        print(f'已重传包编号: {pkt_num}')
                        pkt_info['timestamp'] = current_time
                        pkt_info['retransmit_count'] += 1
                        pkt_info['retransmitted'] = True
                        # 拥塞窗口调整
                        ssthresh = max(cwnd / 2, 2 * MSS)
                        cwnd = MSS  # 重置 cwnd 到 1 MSS
                        dup_ack_count = 0  # 重置重复ACK计数器
                        # 增加 RTO（指数回退）
                        RTO = min(RTO * 2, MAX_RTO)

                # 计算已发送但未确认的数据包总大小（inflight_size）
                inflight_size = sum(len(pending_acks[pkt_num]['packet']) for pkt_num in pending_acks)

                # 发送数据包（遵循流量控制和拥塞控制）
                while inflight_size + MSS <= max(cwnd, MSS) and not sent_all_packets:
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
                            pending_acks[packet_number] = {
                                'timestamp': time.time(),
                                'packet': packet,
                                'retransmit_count': 0,
                                'retransmitted': False
                            }
                            packet_number += 1  # 递增包编号
                            stream['offset'] += len(data)
                            stream['data_packets_sent'] += 1  # 递增已发送数据包计数

                            # 记录发送的数据
                            with open(sender_log_file, 'a', newline='') as csvfile:
                                writer = csv.DictWriter(csvfile, fieldnames=['timestamp', 'stream_id', 'offset', 'max_stream_data'])
                                writer.writerow({
                                    'timestamp': time.time(),
                                    'stream_id': stream_id,
                                    'offset': stream['offset'],
                                    'max_stream_data': stream['max_stream_data']
                                })
                            inflight_size += len(packet)
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

                # 记录指标
                with open(metrics_log_file, 'a', newline='') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=['timestamp', 'packet_number', 'rtt', 'srtt', 'rttvar', 'rto', 'cwnd', 'ssthresh', 'state', 'inflight_packets'])
                    writer.writerow({
                        'timestamp': time.time(),
                        'packet_number': packet_number,
                        'rtt': rtt_sample if 'rtt_sample' in locals() else '',
                        'srtt': SRTT if SRTT is not None else '',
                        'rttvar': RTTVAR if RTTVAR is not None else '',
                        'rto': RTO,
                        'cwnd': cwnd,
                        'ssthresh': ssthresh,
                        'state': state.name,
                        'inflight_packets': len(pending_acks)
                    })

                # 检查是否所有数据都已发送且已确认
                if sent_all_packets and not pending_acks:
                    print('所有数据包已发送并被确认。')
                    close_packet_type = 2  # 使用短包头格式
                    close_header = create_quic_header(close_packet_type, packet_number, dest_conn_id, source_conn_id)
                    # 构建 CONNECTION_CLOSE 帧
                    error_code = 0x00  # 正常关闭
                    frame_type = 0x1c  # CONNECTION_CLOSE 帧类型
                    reason_phrase = b'Client closing connection'
                    reason_length = len(reason_phrase)
                    connection_close_frame = struct.pack(f'!BHB{reason_length}s', frame_type, error_code, reason_length,
                                                         reason_phrase)
                    close_packet = close_header + connection_close_frame
                    s.sendto(close_packet, (dest_ip, dest_port))
                    print('发送 CONNECTION_CLOSE 帧，关闭连接')
                    state = ClientState.CLOSED
                    break

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
