import unittest
import logging

asset_state_v2_cfg = {
    "endpoint": "https://gl-game.tsubasa-dreamteam.com/ep73",
    "startup_key": "Sqm+kQWVo679raYK",
    "pubkey": """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCp0fjPgtnWaWq2LGfLzR9HraEX
D9M76SXhJH2ld1oE/U6kVfggpfwXI42SEVmEQytOPn6RjVdBATYaBgKsMbPee1pR
8Tk1sQD6bA+8IBPoSogqZYSNdRPnAaASCNEVOd+29hjS0mMCLUu7XezctkAjkW8a
WsRwn+8fvXuU2pSg9wIDAQAB
-----END PUBLIC KEY-----
""",
    "log": "dteam_en",
    "il2cpp_hashes": [
        "e4865e974b2f1f0fd58bd84b74cb1c16",
        "a4aab521a9b1797911fcf53acdca018b2e3dac6e",
        "190df06f27da818961fac74cb9fec04070efb877d38fbc8f86a569966c262ec4"
    ],
    "jackpot_core_hashes": [
        "5ac56cc662fb614ef3d5a3100a051fad",
        "6ef04058dd70f6afc29a02d59013ecd8d3f1bc99",
        "02f382b23eaa614a8d32732a4e6c4fe4961638fd2f173b5f829bf6e6531b19b4"
    ],
    "package_signatures": [
        "cc7fc16f08a956bc79db2acd307ddec0",
        "37815158d9a6d66a7c78b91a4fac7491c43fa3fe",
        "525bc7c8daca6982c32729b3132e1186733ff900e9ccb37a033b49a34f1363c9"
    ]
}

asset_state_v2_expected = [
    (511955072,
     "IBkw98OzqJGnNiTK04CA+J8PJgQnu4KQF99DyoJvB+TsfDGt3XgYpsG3zRW001oKI9"
     + "ncBweh4BwvsOpylha8aY4USed3AewtB3Ucc6628o0vVY1DLLRng7lu+q6cmI/fETjS"
     + "g2j3YSFXDJPQJh53GCG1FXPjWw0iZk7IR4R6oHuI"),
    (792011477,
     "dxNjup6dk6z1SXDMR6f6YVJ9JlV5F5iOiV2aT+qXBE36reMxWvHilMU7FlEBvCzGls"
     + "lUmxLckMO4mOAAr8kB4ItGLygmtrSZWLSjaT4b5hvX")
]


class TestGachanator(unittest.TestCase):
  def test_asset_state_v2(self):
    from gachanator import KlabHttpApi
    api = KlabHttpApi(**asset_state_v2_cfg)
    for user_id, expected in asset_state_v2_expected:
      digits = str(user_id)
      digits = digits[::-1]
      digits = digits[2:7].encode("ascii")
      self.assertEqual(api.asset_state_v2(digits), expected)


if __name__ == "__main__":
  logging.basicConfig(level=logging.DEBUG)
  unittest.main()
