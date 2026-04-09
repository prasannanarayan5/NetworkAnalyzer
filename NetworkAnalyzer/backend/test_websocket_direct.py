#!/usr/bin/env python
"""Test WebSocket connection directly"""

import asyncio
import json
import websockets

async def test_websocket():
    uri = "ws://localhost:8000/ws/live"
    print(f"[TEST] Connecting to {uri}")
    
    try:
        async with websockets.connect(uri) as websocket:
            print("[TEST] ✓ Connected")
            
            # Wait for messages
            for i in range(5):
                try:
                    msg = await asyncio.wait_for(websocket.recv(), timeout=2.0)
                    data = json.loads(msg)
                    print(f"[TEST] Batch #{i+1}: type={data.get('type')}, "
                          f"pkts={len(data.get('packets', []))}, "
                          f"stats={data.get('stats', {}).get('total_packets', 0)}")
                except asyncio.TimeoutError:
                    print(f"[TEST] ⏱ Timeout waiting for batch #{i+1}")
                    break
                except Exception as e:
                    print(f"[TEST] Error: {type(e).__name__}: {e}")
                    break
                    
    except Exception as e:
        print(f"[TEST] Connection error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()

print("[TEST] Running WebSocket test...")
print("[TEST] Make sure backend is running and capture is ACTIVE!")
asyncio.run(test_websocket())
