from websockets import serve
from scapy.all import Raw, AsyncSniffer, Packet
from functools import lru_cache
from collections import deque
from typing import TypedDict

import time
import brotli
import struct
import asyncio
import websockets.asyncio
import logging

# 로깅 레벨을 DEBUG로 변경하여 더 자세한 정보 출력
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("mdm2.log", encoding="utf-8"),
        logging.StreamHandler()  # 콘솔에도 출력하려면 포함
    ]
)

# 로거 인스턴스 생성
logger = logging.getLogger(__name__)

# WebSocket
PORT = 16000

# Constants
PACKET_START = b'\x65\x27\x00\x00\x00\x00\x00\x00\x00'
PACKET_END = b'\xe0\x27\x00\x00\x00\x00\x00\x00'

# Flag bits definition
FLAG_BITS = (
    (0, 'crit_flag', 0x01),
    (0, 'unguarded_flag', 0x04),
    (0, 'break_flag', 0x08),
    (0, 'first_hit_flag', 0x40),
    (0, 'default_attack_flag', 0x80),
    (1, 'multi_attack_flag', 0x01),
    (1, 'power_flag', 0x02),
    (1, 'fast_flag', 0x04),
    (1, 'dot_flag', 0x08),
    (1, 'unknown_flag', 0x80),
    (3, 'add_hit_flag', 0x08),
    (3, 'bleed_flag', 0x10),
    (3, 'dark_flag', 0x20),
    (3, 'fire_flag', 0x40),
    (3, 'holy_flag', 0x80),
    (4, 'ice_flag', 0x01),
    (4, 'electric_flag', 0x02),
    (4, 'poison_flag', 0x04),
    (4, 'mind_flag', 0x08),
    (4, 'not_dot_flag', 0x10),
)
SKILL_ID = {
    "01c48e33": "ExpertArcher_MultiShot",
    "ac5c5e38": "ExpertArcher_Richochet_ArrowRevolver",
    "91d3cb65": "ExpertArcher_Richochet_SideStepRight",
    "8bffef6c": "ExpertArcher_Richochet_HawkShot",
    "30efb51b": "ExpertArcher_Richochet_EscapeStep",
    "95ff1a3c": "ExpertArcher_ArrowRevolver",
    "9265fb67": "ExpertArcher_ArrowRevolver_Tier2A_Bonus",
    "ad9a3379": "ExpertArcher_MagnumShotEnd",
    "45ed7f1e": "ExpertArcher_SideStepRight",
    "18aa950a": "ExpertArcher_HawkShot",
    "9e5b953d": "ExpertArcher_HawkShot_Unguarded",
    "fe6d8f7e": "ExpertArcher_EscapeStep",
    "e714dd6a": "ExpertArcher_FireArrow",
    "61e5a00b": "ExpertArcher_FireArrow_AddDMG",
    "d48e317d": "Ranged_Default_Attack"
}

class DamageContent(TypedDict):
    type: int
    timestamp: int
    used_by: str
    target: str
    skill_name: str
    skill_id: str
    damage: int
    flags: dict

@lru_cache(maxsize=256)
def extract_flags(flags: bytes) -> dict:
    result = {}
    for index, name, mask in FLAG_BITS:
        try:
            result[name] = 1 if (flags[index] & mask) != 0 else 0
        except IndexError:
            result[name] = 0

    if result['dot_flag'] and result['holy_flag']:
        for k in ['ice_flag', 'electric_flag', 'poison_flag', 'mind_flag', 'not_dot_flag']:
            result[k] = 0

    return result

def parse_damage(data: bytes) -> DamageContent:
    pivot = 0

    user_id, pivot = data[pivot:pivot+4].hex(), pivot+4
    b, pivot =  data[pivot:pivot+4].hex(), pivot+4
    target_id, pivot = data[pivot:pivot+4].hex(), pivot+4
    d, pivot =  data[pivot:pivot+4].hex(), pivot+4
    damage, pivot =  int.from_bytes(data[pivot:pivot+4], byteorder='little'), pivot+4
    f, pivot =  data[pivot:pivot+4].hex(), pivot+4
    flags, pivot =  data[pivot:pivot+7], pivot+7
    e, pivot =  data[pivot:pivot+4].hex(), pivot+4

    return {
        "type": 10701,
        "timestamp": round(time.time() * 1000),
        "used_by": user_id,
        "target": target_id,
        "skill_name": None,
        "skill_id": None,
        "damage": damage,
        "flags": None
    }

def parse_skill(data):
    pivot = 0

    user_id, pivot = data[pivot:pivot+4].hex(), pivot+4
    b, pivot = data[pivot:pivot+4].hex(), pivot+4
    target_id, pivot = data[pivot:pivot+4].hex(), pivot+4
    d, pivot = data[pivot:pivot+4].hex(), pivot+4
    action_id, pivot = data[pivot:pivot+4].hex(), pivot+4
    f, pivot = data[pivot:pivot+4].hex(), pivot+4
    flags, pivot = data[pivot:pivot+7], pivot+7
    e, pivot = data[pivot:pivot+4].hex(), pivot+4

    flags = extract_flags(flags)

    return {
        "type": 10299,
        "timestamp": round(time.time() * 1000),
        "used_by": user_id,
        "target": target_id,
        "skill_name": parse_skill_name(action_id, flags, e),
        "skill_id": action_id,
        "damage": None,
        "flags": flags,
    }

def parse_skill_name(skill_id: str, flags: dict, e: str) -> str:
    skill_name = SKILL_ID.get(skill_id, f"Idle({skill_id})")
    if 'Idle' in skill_name:
        if flags['dot_flag']:
            prefix = 'DOT' if flags['dot_flag'] else 'UNKNOWN'
            suffix = ''.join(name for key, name in [
                ('ice_flag', 'ICE'),
                ('fire_flag', 'FIRE'),
                ('electric_flag', 'ELECTRIC'),
                ('holy_flag', 'HOLY'),
                ('bleed_flag', 'BLEED'),
                ('poison_flag', 'POISON'),
                ('mind_flag', 'MIND'),
                ('dark_flag', 'DARK'),
            ] if flags.get(key))
            skill_name = '_'.join([prefix, suffix])
        
        if skill_id == '0000000000000000' and e == '00000001':
            if flags['dark_flag']:
                skill_name = "Ruined_Mark"
            else:
                skill_name = "Giant_Arm"

    return skill_name

def merge_contents(content1: DamageContent, content2: DamageContent = None) -> DamageContent:
    merged = content1.copy()

    if content2:
        if merged['damage'] is None:
            merged['damage'] = content2.get('damage')

    else:
        if merged.get("skill_name") is None:
            merged["skill_name"] = "Unknown"
        if merged.get("skill_id") is None:
            merged["skill_id"] = "Unknown"
        if merged.get("damage") is None:
            merged["damage"] = 0
        if merged.get("flags") is None:
            merged["flags"] = {}

    return merged

def format_and_pack_log(damage_data: DamageContent):
    flags = damage_data['flags']
    flags['dot_flag'] = (
        1 if flags.get('ice_flag') == 1 else
        2 if flags.get('fire_flag') == 1 else
        3 if flags.get('electric_flag') == 1 else
        4 if flags.get('holy_flag') == 1 else
        5 if flags.get('bleed_flag') == 1 else
        6 if flags.get('dark_flag') == 1 else
        7 if flags.get('poison_flag') == 1 else
        8 if flags.get('mind_flag') == 1 else
        0
    )

    timestamp = damage_data['timestamp'] # 8 bytes
    used_by = bytes.fromhex(damage_data['used_by'])  # 4 bytes
    target = bytes.fromhex(damage_data['target'])    # 4 bytes
    damage = int(damage_data['damage'])

    # flags1 (16bit)
    flags1 = 0
    flags1 |= (int(flags.get('crit_flag', 0))        & 1) << 0
    flags1 |= (int(flags.get('add_hit_flag', 0))     & 1) << 1
    flags1 |= (int(flags.get('unguarded_flag', 0))   & 1) << 2
    flags1 |= (int(flags.get('break_flag', 0))       & 1) << 3
    flags1 |= (int(flags.get('power_flag', 0))       & 1) << 4
    flags1 |= (int(flags.get('fast_flag', 0))        & 1) << 5
    flags1 |= (int(flags.get('dot_flag', 0))         & 0b1111) << 6

    # 최종 struct 포맷 (flags2 제외됨)
    fmt = '<Q4s4sIH'  # 4+4+4+4+2 = 18B

    base_pack = struct.pack(fmt, timestamp, used_by, target, damage, flags1)

    skill_bytes = damage_data['skill_name'].encode('utf-8')
    skill_len = len(skill_bytes)
    if skill_len > 255:
        skill_bytes = skill_bytes[:255]
        skill_len = 255

    # skill_name_length(1B) + skill_name bytes
    return base_pack + struct.pack('B', skill_len) + skill_bytes

class PacketStreamer:
    def __init__(self, filter_expr: str = "tcp and src port 16000"):
        self.queue: asyncio.Queue[Packet] = asyncio.Queue()
        self.sniffer = AsyncSniffer(filter=filter_expr, prn=self._enqueue_packet)
        self.loop = asyncio.get_event_loop()
        self.buffer:bytes = b''

        self.batch: list[bytes] = []
        self.batch_lock = asyncio.Lock()

    async def stream(self, websocket) -> None:
        self.sniffer.start()
        time.sleep(0.06)

        send_task = asyncio.create_task(self._send_batch_periodically(websocket))
        consumer_task = asyncio.create_task(self._process(websocket))
        try:
            await websocket.wait_closed()
        finally:
            consumer_task.cancel()
            send_task.cancel()
            self.sniffer.stop()
            self.sniffer.join()

    async def _send_batch_periodically(self, websocket) -> None:
        while True:
            await asyncio.sleep(1)  # 1초 대기
            async with self.batch_lock:
                if not self.batch:
                    continue

                try:
                    # 각 패킷 앞에 2바이트 길이 붙이기
                    packed_data = b''.join(
                        struct.pack('<H', len(pkt)) + pkt for pkt in self.batch
                    )
                    await websocket.send(packed_data)
                    logger.info(f"Sent batch of {len(self.batch)} packets to WebSocket")
                    self.batch.clear()
                except Exception as e:
                    logger.debug(f"Error sending batch to WebSocket: {e}")
                    break

    def _enqueue_packet(self, pkt: Packet) -> None:
        self.loop.call_soon_threadsafe(self.queue.put_nowait, pkt)

    def _packet_parser(self, data: bytes) -> tuple[list,int]:
        res = []
        stack = deque()
        pivot = 0
        buffer_size = len(data)

        while(pivot < len(data)):
            
            # 패킷 시작 부분 찾기
            pivot = data.find(PACKET_START, pivot)
            if pivot == -1:
                break 
            if data.find(PACKET_END, pivot+9) == -1:
                break
            pivot += 9

            while ( buffer_size > pivot + 9):

                data_type = int.from_bytes(data[pivot:pivot+4], byteorder='little')
                length = int.from_bytes(data[pivot+4:pivot+8], byteorder='little')
                encode_type = data[pivot+8]

                if data_type == 0:
                    break
                
                if buffer_size <= pivot + 9 + length:
                    break

                content = data[pivot+9:pivot+9+length]

                if encode_type == 1:
                    try:
                        content = brotli.decompress(content)                
                    except brotli.error as e:
                        logger.debug(f"Brotli decompression error: {e}")
                        pass
                
                if data_type == 10701:
                    content = parse_damage(content)
                    if content['damage'] < 10000000 and content['damage'] > 0:
                        stack.append(content)

                elif data_type == 10299:
                    content = parse_skill(content)
                    if stack:
                        temp = stack.pop()
                        if temp['used_by'] == content['used_by'] and temp['target'] == content['target']:
                            res.append(format_and_pack_log(merge_contents(content, temp)))

                        else:
                            res.append(format_and_pack_log(merge_contents(temp)))
                            res.append(format_and_pack_log(merge_contents(content)))
                            while stack:
                                temp = stack.pop()
                                res.append(format_and_pack_log(merge_contents(temp)))

                pivot += 9 + length

        return (res, pivot)
    
    async def _process(self, websocket) -> None:
        while True:
            try:
                pkt: Packet = await self.queue.get()
            except asyncio.CancelledError as e:
                logger.debug(f"Packet processing cancelled: {e}")
                break

            if pkt.haslayer(Raw):
                self.buffer = bytes(pkt[Raw].load)
                
                if len(self.buffer) > 1024 * 4 * 4:
                    self.buffer = self.buffer[len(self.buffer)//2:]
                    logger.info("Buffer size exceeded, trimming to half")

                parsed, pivot = self._packet_parser(self.buffer)
                self.buffer = self.buffer[pivot:]

                if parsed:
                    async with self.batch_lock:
                        self.batch.extend(parsed)

async def main() -> None:
    async def wsserve(websocket) -> None:
        streamer = PacketStreamer()
        await streamer.stream(websocket)
    async with serve(wsserve, '0.0.0.0', 8000):
        logger.info("WebSocket server started on ws://0.0.0.0:8000")
        await asyncio.Future()  # run forever

if __name__ == '__main__':
    asyncio.run(main())