# Golden bytes（黄金字节）

来源：2026-09-20 E7 轮在 C9800-fresh 17.14.01 上验证可被 WLC 完整处理的真实报文
（life44：Join→Result Code=0→Registered，RD=-C；见 docs/evidence/re-20260919/life44.log）。
固定输入生成（session_id=全零、local_ip=192.168.10.128、SeqNum 固定），
供 builders 的逐字节回归测试使用。

| 文件 | 长度 | sha256 | 说明 |
| --- | --- | --- | --- |
| golden_disc.bin | 252 | 021f41479e8e23ef18171b3d18d5094aa6e489289c2869c3af89f6e5795200ed | Discovery Request（radio 0/1、model C9105AXI-C） |
| golden_join.bin | 318 | 5f494a473a18e9655e7c63dea3bcb3d765299f7c2e281b3bc00ee276d82ef6b2 | Join Request（Result Code=0 版本） |
| golden_csr.bin | 130 | d9bd0b6799b7588b27f706ce08aafb2bfdb240b862a0878f7a0ca9acb9e57c0e | Configuration Status Request（含 VSP-126 监管域 0x0010=-C） |
| golden_cse.bin | 86 | 81d75f9ae4da211277678f73c62505eec631d6eb1fbdba384a11ce280914a1dc | Change State Event Request |
| golden_echo.bin | 24 | 7cbdf72c477ab1d9b2ebdd15623000349e991f7a7e25dc5d1c8e77f3d99cf155 | Echo Request（SeqNum=3） |

身份：AP MAC 10:a8:29:92:61:00、radio MAC 同、名称 AP10A8.2901.D6B0、
型号 C9105AXI-C、radio (0, 802.11b|g|n=0x0d) 与 (1, 802.11a|n=0x0a)。

长度与 sha256 以文件实测为准（2026-09-20 复核：`golden_csr.bin`/`golden_cse.bin` 两行此前
为重新生成前的旧值 132B/46B，已按实测更正为 130B/86B，`tests/test_session_builders.py`
的逐字节回归 17/17 通过）。
