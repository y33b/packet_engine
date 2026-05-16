import asyncio
import json
import numpy as np
import websockets
from pyod.models.iforest import IForest
from collections import defaultdict, deque

GO_WS = "ws://localhost:8080/ws"  

model = IForest(contamination=0.05)
buffer = []
trained = False

history = defaultdict(lambda: deque(maxlen=50))


def features(e):
    return np.array([
        float(e.get("PacketRate", 0)) / 100,
        float(e.get("UniquePorts", 0)) / 50,
        float(e.get("FailedAtt", 0)) / 20
    ])


async def run():
    global trained

    async with websockets.connect(GO_WS) as ws:
        print("🧠 CONNECTED TO GO ENGINE")

        while True:
            msg = await ws.recv()
            data = json.loads(msg)


            e = data.get("data", data)

            ip = e.get("SrcIP", "unknown")

            history[ip].append(e)

            x = features(e)
            buffer.append(x)

            if len(buffer) > 50 and not trained:
                model.fit(np.array(buffer))
                trained = True
                print("🔥 MODEL TRAINED")

            if not trained:
                continue

            anomaly = int(model.predict([x])[0])
            score = float(model.decision_function([x])[0])

            output = {
                "IP": ip,
                "Type": "ATTACK" if anomaly else "NORMAL",
                "Risk": round(score, 4),
                "Message": "LIVE ML"
            }

            print(output)


asyncio.run(run())
