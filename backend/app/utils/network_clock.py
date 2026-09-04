"""
网络时钟：把 datetime.now / datetime.utcnow / time.time 重定向到真实网络时间。

设计要点
--------
- 启动时立即通过 NTP（默认 ntp.aliyun.com，国内可达）校准一次，得到
  offset = network_now - server_now（秒），后面所有"现在"= 服务器时间 + offset。
- 后台 daemon 线程每 1 小时重新校准一次，避免服务器本地时钟漂移。
- NTP 失败时保持上一次 offset（不阻塞业务），启动后再补偿。
- 使用标准库 socket/struct 走 NTP 协议，**不引入新依赖**。
- 同时给后端业务暴露 now() / utcnow() / epoch() 三个公共函数，**用法与 datetime 原生相同**。
"""
import time as _time
import logging
import socket
import struct
import threading
from datetime import datetime, timedelta

log = logging.getLogger("network_clock")

# 校准参数
NTP_HOST = "ntp.aliyun.com"   # 国内阿里云 NTP，可按需改成 pool.ntp.org
NTP_PORT = 123
NTP_TIMEOUT = 3                # 秒，单次校准最长等 3s
RECHECK_INTERVAL = 3600         # 秒，定时重校准周期

# 全局状态
_offset: float = 0.0           # network_now - server_now（秒）
_lock = threading.Lock()

# 保存原始 time.time 引用，用于在 _calibrate() 中算"真实差值"
_orig_time = _time.time


def _fetch_ntp(host: str = NTP_HOST, port: int = NTP_PORT, timeout: int = NTP_TIMEOUT) -> float | None:
    """NTP 协议取 UTC 时间戳（UNIX 秒）。失败返回 None。"""
    try:
        # NTP v3 client request: LI=0, VN=3, Mode=3 -> 0x1B + 47 bytes zero
        msg = b"\x1b" + 47 * b"\0"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(msg, (host, port))
        data, _ = sock.recvfrom(1024)
        sock.close()
        # NTP 时间戳：自 1900-01-01 起秒数；转 UNIX（自 1970-01-01）需减 2208988800
        ntp_epoch = struct.unpack("!12I", data)[10] - 2208988800
        return float(ntp_epoch)
    except Exception as e:
        log.warning("NTP 校准失败 host=%s:%s err=%s", host, port, e)
        return None


def _calibrate() -> bool:
    """重新拉一次 NTP，更新全局 offset。失败时保持上次值，返回是否成功。"""
    global _offset
    ntp_now = _fetch_ntp()
    if ntp_now is None:
        log.warning("NTP 校准失败，保持 offset=%.3fs", _offset)
        return False
    # 用 *原始* time.time() 算 offset，避免被 monkey patch 干扰
    new_offset = ntp_now - _orig_time()
    with _lock:
        _offset = new_offset
    log.info(
        "NTP 校准成功 offset=%.3fs (网络比服务器快/慢 %.1f 秒)",
        new_offset, new_offset,
    )
    return True


def _loop() -> None:
    """后台线程：每小时重新校准一次，防止服务器本地时间漂移。"""
    while True:
        _time.sleep(RECHECK_INTERVAL)  # 这里 sleep 必须用真实秒数，不能用 epoch()
        try:
            _calibrate()
        except Exception as e:
            log.exception("定时校准异常: %s", e)


def _start() -> None:
    """启动入口：立即校准 + 后台线程持续校准。失败也不抛（保持 offset=0 = 退化到服务器时间）。"""
    try:
        _calibrate()
    except Exception as e:
        log.exception("启动 NTP 校准异常: %s", e)
    t = threading.Thread(target=_loop, daemon=True, name="ntp-calibrator")
    t.start()


# -------- 公共 API（业务侧可直接 from .network_clock import now/utcnow/epoch）--------

def offset_seconds() -> float:
    """返回当前 offset（network - server，单位秒）。"""
    with _lock:
        return _offset


def now() -> datetime:
    """等价 datetime.now()，但用的是网络时间。"""
    return datetime.now() + timedelta(seconds=offset_seconds())


def utcnow() -> datetime:
    """等价 datetime.utcnow()，但用的是网络 UTC 时间。"""
    return datetime.utcnow() + timedelta(seconds=offset_seconds())


def epoch() -> float:
    """等价 time.time()，但用的是网络 epoch 秒。"""
    return _orig_time() + offset_seconds()


# 模块导入即启动
_start()
