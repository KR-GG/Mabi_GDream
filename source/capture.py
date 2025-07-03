import asyncio
import brotli
import struct
import websockets
import threading
from scapy.all import sniff, Raw, TCP
from collections import deque
from functools import lru_cache
import time

# ---------- CONFIGURATION ----------
TARGET_PORT = 16000
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

connection_buffer = bytearray()
sending_queue = deque()
current_damage = None
connected_clients = set()
main_loop = None
send_data_running = False
batched_payloads = deque()
batch_lock = asyncio.Lock()
batch_sender_task = None

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
                        print(f"Brotli decompression error: {e}")
                        continue

                if data_type in (10701, 10299):
                    result.append({
                        "type": data_type,
                        "timestamp": round(time.time() * 1000),
                        "content": content
                    })

            except Exception as e:
                print(f"[ERROR] Failed to parse inner payload: {e}")
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
                print(f"[INFO] Sent batch of {len(batch)} packets")
            except Exception as e:
                print(f"[ERROR] Failed to send batch: {e}")
                break
    except asyncio.CancelledError:
        print("[INFO] Batch sender cancelled")

async def handler(websocket):
    global batch_sender_task
    print(f"[INFO] Client connected: {websocket.remote_address}")
    connected_clients.add(websocket)
    batch_sender_task = asyncio.create_task(send_batch_periodically(websocket))
    try:
        async for _ in websocket:
            pass
    except Exception as e:
        print(f"[ERROR] WebSocket error: {e}")
    finally:
        connected_clients.discard(websocket)
        if batch_sender_task:
            batch_sender_task.cancel()
            try:
                await batch_sender_task
            except asyncio.CancelledError:
                pass
        print(f"[INFO] Client disconnected: {websocket.remote_address}")

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
        print(f"[ERROR] handle_packet failed: {e}")

async def start_websocket_server():
    global main_loop
    main_loop = asyncio.get_running_loop()
    async with websockets.serve(handler, "127.0.0.1", 8000, max_size=None):
        print("[INFO] WebSocket server running on ws://127.0.0.1:8000")
        await asyncio.Future()

def main():
    thread = threading.Thread(
        target=lambda: sniff(filter=f"tcp port {TARGET_PORT}", prn=handle_packet, store=0)
    )
    thread.daemon = True
    thread.start()
    asyncio.run(start_websocket_server())

if __name__ == "__main__":
    main()
