"""
VXLAN 封装/解封工具模块

VXLAN (RFC 7348): 通过 UDP 封装二层以太网帧，
支持在三层网络中传输二层流量。

VXLAN 头部:
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |R|R|R|R|I|R|R|R|            Reserved                           |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                VXLAN Network Identifier (VNI)   |   Reserved  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

外层封装:
  [Eth Header] [IP Header] [UDP Header (dst=4789)] [VXLAN Header] [内层 Eth 帧]
"""

import struct
import socket
import logging

logger = logging.getLogger("dns-proxy.vxlan")

# VXLAN 默认端口
VXLAN_PORT = 4789

# VXLAN 标志位：I=1 表示 VNI 有效
VXLAN_FLAGS_I_SET = 0x08


class VXLANHeader:
    """
    VXLAN 头部数据类。
    
    Attributes:
        vni: VXLAN Network Identifier (24-bit, 0-16777215)
        flags: 标志位（I=0x08）
    """
    __slots__ = ('vni', 'flags')
    
    def __init__(self, vni: int, flags: int = VXLAN_FLAGS_I_SET):
        if not (0 <= vni <= 0xFFFFFF):
            raise ValueError(f"VNI 超出范围 (0-16777215): {vni}")
        self.vni = vni
        self.flags = flags
    
    def pack(self) -> bytes:
        """将 VXLAN 头部打包为 8 字节。"""
        return struct.pack('!I', (self.flags << 24) | (self.vni << 8) | 0)
    
    @staticmethod
    def unpack(data: bytes) -> 'VXLANHeader':
        """从 8 字节解码 VXLAN 头部。"""
        if len(data) < 8:
            raise ValueError(f"VXLAN 头部需要 8 字节，收到 {len(data)}")
        val = struct.unpack('!I', data[:4])[0]
        flags = (val >> 24) & 0xFF
        vni = (val >> 8) & 0xFFFFFF
        return VXLANHeader(vni=vni, flags=flags)
    
    def __repr__(self) -> str:
        return f"VXLANHeader(vni={self.vni}, flags=0x{self.flags:02x})"


def encap_vxlan(inner_frame: bytes, vni: int,
                outer_src_mac: str, outer_dst_mac: str,
                outer_src_ip: str, outer_dst_ip: str,
                vxlan_port: int = VXLAN_PORT) -> bytes:
    """
    构造完整的 VXLAN 封装包。
    
    外层: [Eth] [IP] [UDP:4789] [VXLAN(8B)] [内层 Eth 帧]
    
    Args:
        inner_frame: 内层完整的以太网帧
        vni: VXLAN VNI (0-16777215)
        outer_src_mac: 外层源 MAC
        outer_dst_mac: 外层目标 MAC
        outer_src_ip: 外层源 IP
        outer_dst_ip: 外层目标 IP
        vxlan_port: VXLAN UDP 端口（默认 4789）
    
    Returns:
        完整的 VXLAN 封装包（bytes）
    """
    vxlan_hdr = VXLANHeader(vni=vni).pack()
    
    # UDP 头部（8 字节）
    udp_length = 8 + len(vxlan_hdr) + len(inner_frame)
    udp_hdr = struct.pack('!HHHH', vxlan_port, vxlan_port, udp_length, 0)
    
    # IP 头部（20 字节，IPv4 无选项，协议 17=UDP）
    ip_hdr = _build_ip_header(outer_src_ip, outer_dst_ip, udp_length)
    
    # 以太网头部
    src_mac_bytes = bytes.fromhex(outer_src_mac.replace("-", "").replace(":", ""))
    dst_mac_bytes = bytes.fromhex(outer_dst_mac.replace("-", "").replace(":", ""))
    eth_hdr = dst_mac_bytes + src_mac_bytes + struct.pack('!H', 0x0800)  # EtherType IPv4
    
    return eth_hdr + ip_hdr + udp_hdr + vxlan_hdr + inner_frame


def decap_vxlan(packet: bytes) -> dict:
    """
    解封 VXLAN 包，提取内层帧和 VNI。
    
    假设外层是纯 IPv4（无 VLAN/隧道标签嵌套）。
    
    Args:
        packet: 完整的 VXLAN 包（从 Eth 头开始）
    
    Returns:
        {
            "inner_frame": 内层以太网帧,
            "vni": VXLAN VNI,
            "outer_src_ip": 外层源 IP,
            "outer_dst_ip": 外层目标 IP,
        }
        解析失败返回 None
    """
    try:
        if len(packet) < 42:  # 14(Eth) + 20(IP) + 8(UDP) + 8(VXLAN) = 50 min
            return None
        
        # 跳过 Ethernet 头 (14 bytes)
        eth_type = struct.unpack('!H', packet[12:14])[0]
        if eth_type != 0x0800:  # 不是 IPv4
            return None
        
        ip_hdr = packet[14:34]
        ip_ver_ihl = ip_hdr[0]
        ihl = (ip_ver_ihl & 0x0F) * 4
        if ihl < 20:
            return None
        
        protocol = ip_hdr[9]
        if protocol != 17:  # 不是 UDP
            return None
        
        outer_src_ip = socket.inet_ntoa(ip_hdr[12:16])
        outer_dst_ip = socket.inet_ntoa(ip_hdr[16:20])
        
        udp_start = 14 + ihl
        udp_dst_port = struct.unpack('!H', packet[udp_start + 2:udp_start + 4])[0]
        
        vxlan_start = udp_start + 8
        vxlan_header = VXLANHeader.unpack(packet[vxlan_start:vxlan_start + 8])
        
        inner_start = vxlan_start + 8
        inner_frame = packet[inner_start:]
        
        return {
            "inner_frame": inner_frame,
            "vni": vxlan_header.vni,
            "outer_src_ip": outer_src_ip,
            "outer_dst_ip": outer_dst_ip,
        }
    except Exception as e:
        logger.debug("VXLAN 解封失败: %s", e)
        return None


def build_vxlan_socket(timeout: float = 1.0) -> socket.socket:
    """
    创建 VXLAN UDP 套接字（绑定 4789 端口）。
    
    Args:
        timeout: 套接字超时（秒）
    
    Returns:
        socket.socket
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    try:
        sock.bind(('0.0.0.0', VXLAN_PORT))
    except OSError as e:
        logger.warning("VXLAN 套接字绑定端口 %d 失败: %s", VXLAN_PORT, e)
    return sock


def _build_ip_header(src_ip: str, dst_ip: str, udp_payload_len: int) -> bytes:
    """
    构造 IPv4 头部（协议 17=UDP）。
    注意：校验和置 0（部分场景可忽略）。
    """
    version_ihl = 0x45  # IPv4, IHL=5 (20 bytes)
    dscp_ecn = 0
    total_length = 20 + udp_payload_len
    identification = 0
    flags_offset = 0
    ttl = 64
    protocol = 17  # UDP
    header_checksum = 0  # 由路径设备填充
    
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    
    header = struct.pack('!BBHHHBBH',
                         version_ihl, dscp_ecn, total_length,
                         identification, flags_offset,
                         ttl, protocol, header_checksum)
    
    return header + src_bytes + dst_bytes
