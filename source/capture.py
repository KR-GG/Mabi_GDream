import asyncio
import brotli
import struct
import time
import threading
import websockets
import logging
import socket
from collections import deque
from scapy.all import sniff, Raw, TCP

# ----- DEBUG FLAG -----
DEBUG_MODE = False # Set to True for debug mode

# ---------- LOGGING SETUP ----------
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))

file_handler = logging.FileHandler("log.log", encoding="utf-8")
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))

logger.addHandler(console_handler)
logger.addHandler(file_handler)

# ---------- CONFIG ----------
TARGET_PORT = 16000
PACKET_START = b'\x68\x27\x00\x00\x00\x00\x00\x00\x00'
PACKET_END = b'\xe3\x27\x00\x00\x00\x00\x00\x00'

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
    # == 궁수 계열 ==
    # -- 궁수 --
    "01c48e33": "궁수_다발사격",
    "ac5c5e38": "궁수_애로우리볼버_도탄",
    "91d3cb65": "궁수_사이드스텝_도탄",
    "8bffef6c": "궁수_호크샷_도탄",
    "30efb51b": "궁수_이스케이프스텝_도탄",
    "95ff1a3c": "궁수_애로우리볼버",
    "9265fb67": "궁수_치명적인사격",
    "ad9a3379": "궁수_매그넘샷",
    "45ed7f1e": "궁수_사이드스텝",
    "a8a27a27": "궁수_사이드스텝",
    "18aa950a": "궁수_호크샷",
    "9e5b953d": "궁수_호크샷_무방비",
    "fe6d8f7e": "궁수_이스케이프스텝",
    "e714dd6a": "궁수_죽음의궤적",
    "61e5a00b": "궁수_죽음의궤적_추가대미지",
    "d48e317d": "궁수_평타",
    # -- 석궁사수 --
    "ed7f8224": "석궁사수_버스터샷",
    "db29f42f": "석궁사수_버스터샷", # 패시브 타수 2배
    "e260fd26": "석궁사수_쇼크익스플로전",
    "16c78909": "석궁사수_쇼크익스플로전", # 패시브 타수 2배
    "1c1e9846": "석궁사수_슬라이딩스텝",
    "6cd67a32": "석궁사수_슬라이딩스텝", # 패시브 타수 2배
    "1c9b785e": "석궁사수_거스팅볼트",
    "e8afa668": "석궁사수_거스팅볼트", # 2타
    "aa00c362": "석궁사수_거스팅볼트", # 3타
    "ecae0f1f": "석궁사수_스프레딩볼트",
    "5e38df69": "석궁사수_스프레딩볼트", # 2타
    "2e2b3f45": "석궁사수_스프레딩볼트", # 3타
    "7a90d03c": "석궁사수_헬파이어",
    "f33ab562": "석궁사수_평타",
    # -- 장궁병 --
    "5c87832f": "장궁병_쉘브레이커", # 초타
    "b7ec2b13": "장궁병_쉘브레이커", # 후속타
    "97be9b63": "장궁병_쉘브레이커", # 추가3타
    "7f18271e": "장궁병_윙스큐어",
    "99552506": "장궁병_하트시커",
    "b45f866f": "장궁병_크래시샷", # 단일
    "f5c65e23": "장궁병_크래시샷", # 범위
    "2772e208": "장궁병_플레임애로우",
    "7f65153c": "장궁병_데스스팅어", # 용화살
    "8ed79117": "장궁병_데스스팅어", # 일반화살
    "b7186350": "장궁병_데들리샷",
    "be53053d": "장궁병_드래곤베인",
    "6fbb7d6b": "장궁병_드래곤베인_추가타",
    "182c8d00": "장궁병_평타",
    # == 전사 계열 ==
    # -- 전사 --
    "05fd4800": "전사",
    # -- 검술사 --
    "30e6d21f": "검술사_강철쐐기",
    "8952c05d": "검술사_쾌검",
    "29bf332d": "검술사_비검:강철쐐기", # 공짜비검
    "9859a672": "검술사_비검:강철쐐기",
    "84c3ad41": "검술사_칼집치기",
    "4181ff34": "검술사_비검:칼집치기", # 공짜비검
    "2e6bb94f": "검술사_비검:칼집치기",
    "255a501a": "검술사_질풍베기",
    "be8ed607": "검술사_비검:질풍베기", # 공짜비검
    "6a53b709": "검술사_비검:질풍베기",
    "ca9a675c": "검술사_간파",
    "9fd94f7b": "검술사_일섬",
    "e6e33b44": "검술사_질풍태세",
    "5a2c3908": "검술사_평타",
    # -- 대검전사 --
    "7284bc19": "대검전사",
    "a598d70d": "대검전사",
    "57a21d10": "대검전사",
    "4daea06c": "대검전사",
    "7585fb0f": "대검전사_회전베기",
    # == 도적 계열 ==
    # -- 도적 --
    "4d3a485e": "도적_쓰로잉봄", # 1스택
    "ef3c6627": "도적_쓰로잉봄", # 2스택
    "83985c2b": "도적_쓰로잉봄", # 3스택
    # -- 격투가 --
    "5f365216": "격투가_차징피스트",
    # -- 듀얼블레이드 --
    "8c6a4c46": "듀블",
    "f7d3d447": "듀블",
    "5d63a242": "듀블",
    "7fbe894a": "듀블",
    # == 마법사 계열 ==
    # -- 마법사 --
    "e6068021": "마법사_라이트닝",
    # -- 화염술사 --
    "c91b933d": "화염술사_래피드파이어",
    "c8b29442": "화염술사_파이어스톰",
    "917c0819": "화염술사_플레임캐논",
    "8ac6b532": "화염술사_플래시오버",
    "fd840a54": "화염술사_익스플로전",
    "ed750901": "화염술사_인페르노",
    "9cfee038": "화염술사_평타",
    # -- 빙결술사 --
    "ab347b11": "빙결술사",
    # -- 전격술사 --
    "c8c6bf4d": "전격술사_낙뢰",
    "583fed24": "전격술사_낙뢰", # 추가대미지
    # == 힐러 계열 ==
    # -- 힐러 --
    "790eef76": "힐러_라이프링크",
    "b57bb62d": "힐러_생명의고동",
    "16572272": "힐러_팬텀페인",
    "28d1975d": "힐러_서먼루미너스",
    "e55fa756": "힐러_평타",
    # -- 사제 --
    "86a5bb31": "사제_서먼링커",
    "aaaa3f00": "사제_디바인윙",
    "5c283951": "사제_켈틱크로스",
    "924a2408": "사제_생츄어리",
    "71d5bf3f": "사제_홀리스피어",
    "d405312f": "사제_평타",
    # -- 수도사 --
    # == 음유시인 계열 ==
    # -- 음유시인 --

    # -- 댄서 --
    "c5044d0e": "댄서_내츄럴턴",
    "84938662": "댄서",
    # -- 악사 --
    "44f40840": "악사_연주:아르페지오",
    "48c8df71": "악사_연주:세레나데",
    "34474241": "악사_연주:세레나데", # 강제로 끊으면
    "02c99c06": "악사_연주:1악장",
    "f22a8b7f": "악사_연주:2악장",
    "b19c831e": "악사_연주:3악장",
    "18ba2846": "악사_기교:크레센도",
    "aeba162a": "악사_기교:클라이맥스",
    "a8951367": "악사_카덴차",
    "1f05391e": "악사_평타",
    "cdc19b37": "악사_강화평타",
}

connection_buffer = bytearray()
sending_queue = deque()
current_damage = None
connected_clients = set()
main_loop = None
send_data_running = False
batched_payloads = deque()
batch_lock = asyncio.Lock()
batch_sender_task = None

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
    except Exception as e:
        logger.error(f"Failed to get local IP address: {e}")
        local_ip = "127.0.0.1"
    finally:
        s.close()
    return local_ip

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

def extract_packets(data: bytes):
    result = []
    pivot = 0
    buffer_size = len(data)

    while pivot < buffer_size:
        start = data.find(PACKET_START, pivot)
        if start == -1:
            break

        end = data.find(PACKET_END, start + len(PACKET_START))
        if end == -1:
            break

        section_end = end + len(PACKET_END)
        payload_start = start + len(PACKET_START)

        if buffer_size < payload_start + 9:
            break

        section_data = data[payload_start:end]
        local_pivot = 0
        section_size = len(section_data)

        while local_pivot + 9 <= section_size:
            try:
                header = section_data[local_pivot:local_pivot + 9]
                data_type, length, encode_type = struct.unpack('<IIB', header)
                local_pivot += 9

                if data_type == 0 or local_pivot + length > section_size:
                    break

                content = section_data[local_pivot:local_pivot + length]
                local_pivot += length

                if encode_type == 1:
                    try:
                        content = brotli.decompress(content)
                    except brotli.error as e:
                        logger.error(f"Brotli decompression error: {e}")
                        continue

                if data_type not in (100253, 10327):
                    logger.info(f"Extracted packet: type={data_type}, length={length}, content={content.hex()}")
                
                if data_type in (10701, 10299, 100178):
                    result.append({
                        "type": data_type,
                        "timestamp": round(time.time() * 1000),
                        "content": content
                    })

            except Exception as e:
                logger.error(f"[ERROR] Failed to parse inner payload: {e}")
                break

        pivot = section_end

    return result, pivot


def format_and_pack_log(data):
    flags = data['flags']
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
    flags1 = 0
    flags1 |= (flags.get('crit_flag', 0) & 1) << 0
    flags1 |= (flags.get('add_hit_flag', 0) & 1) << 1
    flags1 |= (flags.get('unguarded_flag', 0) & 1) << 2
    flags1 |= (flags.get('break_flag', 0) & 1) << 3
    flags1 |= (flags.get('power_flag', 0) & 1) << 4
    flags1 |= (flags.get('fast_flag', 0) & 1) << 5
    flags1 |= (flags.get('dot_flag', 0) & 0b1111) << 6
    packed = struct.pack(
        '<Q4s4sIH',
        data['timestamp'],
        bytes.fromhex(data['used_by']),
        bytes.fromhex(data['target']),
        data['damage'],
        flags1
    )
    skill_bytes = data['skill_name'].encode('utf-8')[:255]
    return packed + struct.pack('B', len(skill_bytes)) + skill_bytes

def parse_skill_name(skill_id, flags, e):
    skill = SKILL_ID.get(skill_id, f"Idle({skill_id})")
    if skill.startswith("Idle("):
        if flags['dot_flag']:
            suffix = ''.join(name for key, name in [
                ('ice_flag', 'ICE'),
                ('fire_flag', 'FIRE'),
                ('electric_flag', 'ELECTRIC'),
                ('holy_flag', 'HOLY'),
                ('bleed_flag', 'BLEED'),
                ('poison_flag', 'POISON'),
                ('mind_flag', 'MIND'),
                ('dark_flag', 'DARK')
            ] if flags.get(key))
            skill = f"DOT_{suffix}"
        if skill_id == '00000000' and e == '00000001':
            skill = "Ruined_Mark" if flags['dark_flag'] else "Giant_Arm"
    return skill

async def enqueue_payload(payload: bytes):
    async with batch_lock:
        batched_payloads.append(payload)

async def send_batch_periodically(websocket):
    try:
        while True:
            await asyncio.sleep(0.3)
            async with batch_lock:
                if not batched_payloads:
                    continue
                batch = list(batched_payloads)
                batched_payloads.clear()

            try:
                # 각 패킷에 2바이트 길이 붙이기
                packed = b''.join(
                    struct.pack('<H', len(pkt)) + pkt for pkt in batch
                )
                await websocket.send(packed)
                logger.info(f"Sent batch of {len(batch)} packets")
            except Exception as e:
                logger.error(f"Failed to send batch: {e}")
                break
    except asyncio.CancelledError:
        logger.info("Batch sender cancelled")

async def handler(websocket):
    global batch_sender_task
    logger.info(f"Client connected: {websocket.remote_address}")
    connected_clients.add(websocket)
    batch_sender_task = asyncio.create_task(send_batch_periodically(websocket))
    try:
        async for _ in websocket:
            pass
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        connected_clients.discard(websocket)
        if batch_sender_task:
            batch_sender_task.cancel()
            try:
                await batch_sender_task
            except asyncio.CancelledError:
                pass
        logger.info(f"Client disconnected: {websocket.remote_address}")

async def send_data():
    global current_damage, send_data_running
    if send_data_running:
        return
    send_data_running = True
    try:
        while sending_queue:
            packet = sending_queue.popleft()
            t = packet['type']
            content = packet['content']
            
            if t == 10701:
                damage = int.from_bytes(content[16:20], 'little')
                if 0 < damage < 1e8:
                    current_damage = {
                        'target': content[8:12].hex(),
                        'damage': damage
                    }
                    logger.debug(f"Current damage set: {current_damage}")
            elif t == 100178:
                damage = int.from_bytes(content[8:12], 'little') - int.from_bytes(content[16:20], 'little')
                if 0 < damage < 1e8:
                    current_damage = {
                        'target': content[0:4].hex(),
                        'damage': damage
                    }
                    logger.debug(f"Current damage set: {current_damage}")
            elif t == 10299 and current_damage:
                used_by = content[0:4].hex()
                target = content[8:12].hex()
                action_id = content[16:20].hex()
                flags = extract_flags(bytes(content[24:31]))
                if target == current_damage['target']:
                    damage_data = {
                        'timestamp': packet['timestamp'],
                        'used_by': used_by,
                        'target': target,
                        'skill_name': parse_skill_name(action_id, flags, content[31:35].hex()),
                        'skill_id': action_id,
                        'damage': current_damage['damage'],
                        'flags': flags
                    }
                    logger.debug(f"Damage data prepared: {damage_data}")
                    current_damage = None
                    payload = format_and_pack_log(damage_data)
                    await enqueue_payload(payload)
    finally:
        send_data_running = False

def handle_packet(pkt):
    global connection_buffer, sending_queue
    try:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            connection_buffer += pkt[Raw].load
            parsed, consumed = extract_packets(connection_buffer)
            if parsed:
                sending_queue.extend(parsed)
                if main_loop:
                    main_loop.call_soon_threadsafe(lambda: main_loop.create_task(send_data()))
            if consumed > 0:
                connection_buffer = connection_buffer[consumed:]
    except Exception as e:
        logger.error(f"handle_packet failed: {e}")

async def start_websocket_server():
    global main_loop
    main_loop = asyncio.get_running_loop()

    ip = get_local_ip()
    port = 8000

    async with websockets.serve(handler, "0.0.0.0", port, max_size=None):
        logger.info(f"WebSocket server running on ws://{ip}:{port}")
        await asyncio.Future()

# ----- DEBUG -----
def make_debug_packet():
    timestamp = int(time.time() * 1000)
    used_by = b"abcd".hex()
    target = b"dead".hex()
    skill_name = "궁수_다발사격"
    damage = 1234
    flags = bytearray(6)
    flags[0] |= 0x01  # crit_flag
    flags[0] |= 0x08  # break_flag
    flags[3] |= 0x40  # fire_flag
    flags[4] |= 0x00

    damage_data = {
        'timestamp': timestamp,
        'used_by': used_by,
        'target': target,
        'skill_name': skill_name,
        'damage': damage,
        'flags': extract_flags(bytes(flags))
    }
    return format_and_pack_log(damage_data)

async def send_debug_loop():
    while True:
        await asyncio.sleep(1.0)
        pkt = make_debug_packet()
        await enqueue_payload(pkt)
        print(f"Debug packet sent: {pkt.hex()}")

def main():
    if not DEBUG_MODE:
        thread = threading.Thread(
            target=lambda: sniff(filter=f"tcp port {TARGET_PORT}", prn=handle_packet, store=0)
        )
        thread.daemon = True
        thread.start()

    async def runner():
        global main_loop
        main_loop = asyncio.get_running_loop()
        if DEBUG_MODE:
            asyncio.create_task(send_debug_loop())
        await start_websocket_server()

    asyncio.run(runner())

if __name__ == "__main__":
    main()
