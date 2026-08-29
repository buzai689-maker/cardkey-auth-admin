# 卡密授权管理后台 (Card-Key Authorization Admin)

一个带**设备绑定**的卡密授权 / 网络验证后台:后台生成卡密 → 发卡 → 客户端用卡密 + 机器码激活并绑定设备 → 到期 / 封禁控制 → 后台管理设备(编辑、换绑、解绑)。

## 功能

- **生成卡密**:按卡类型批量生成随机唯一码(去易混字符),支持前缀 / 长度 / 分组,导出 txt 分发
- **卡密管理**:列表 / 筛选(状态、类型、批次、关键字)/ 详情、封禁 / 解封、编辑(可绑设备数、到期调整、备注)、重置、删除
- **卡类型**:时长卡(天 / 周 / 月 / 永久)与点数卡,每类型设默认可绑设备数
- **设备管理**:查看绑定设备、**编辑设备**(名称 / 备注 / 换绑机器码)、**解绑设备**(释放绑定位)
- **客户端验证 API**:`activate` / `verify` / `unbind`
- 仪表盘统计、验证日志 + 后台操作审计、管理员(RBAC:super / operator)、站点设置

## 技术栈

FastAPI + SQLAlchemy 2.0 + SQLite(可切 MySQL)+ Jinja2 服务端渲染。单进程、无前端构建、无 CDN 依赖。

## 快速开始

```bash
# 1. (可选) 安装依赖
pip install -r requirements.txt

# 2. (可选) 灌入演示卡类型 + 一批卡密
python -m scripts.seed

# 3. 启动
python run.py
# 或: uvicorn app.main:app --reload
```

打开 http://127.0.0.1:8000/admin

首次启动自动创建超级管理员(可在 `.env` 覆盖):

| 用户名 | 密码 |
| --- | --- |
| `admin` | `admin888` |

## 客户端验证 API

客户端只有**一个入口**:加密信封 `POST /api/v1/secure`(明文端点已关闭,见下文「全程加密」)。内层是
`{op, code, device_id, ...}`,`op ∈ activate | verify | unbind | heartbeat | session`;
解开后返回结构 `{"success": bool, "message": str, "data": {...} | null}`(session/heartbeat 另带签名回执)。

参考客户端 `examples/client.py` 封装了全过程(取机器码 → 握手 → 心跳),照它移植即可;
`data` 字段:`status` / `app` / `type` / `activated_at` / `expires_at` / `max_devices` / `bound_devices` / `remaining_count` / `heartbeat`。

## 软件加密(客户端保护 / 网络验证)

只做布尔校验(`if success: run`)一条 `je→jmp` 就爆破了。真正的强度来自**把密钥放服务器、用授权门控**:软件核心加密分发,验证通过才下发解密密钥。

协议在应用层完成密钥交换 + 服务器签名,不依赖 TLS(授权用户能拦自己的 TLS),抗中间人:

```
GET  /api/v1/pubkey    -> 服务器 Ed25519 公钥(嵌进客户端做 pinning)
POST /api/v1/session   {code, device_id, client_pub(X25519,b64), nonce(b64)}
     校验卡 + 绑定设备后返回 {success, body, sig}:
       sig  = Ed25519(server_priv, frame(AAD, client_pub, nonce, body))
       body = {server_pub, server_nonce, gcm_nonce, wrapped_key, card, ts, client_nonce}
       wrapped_key = AES-GCM(session_key, K_payload)
       session_key = HKDF(ECDH(server_eph, client_pub), salt=client_nonce+server_nonce)
```

客户端:验签(pinned pub)→ 校验 nonce/ts → ECDH 出 session_key → 解出 `K_payload` → 解密随程序分发的 `core.enc` → 内存加载运行。patch 掉校验分支没用——二进制里没有密钥,签名/ECDH 也伪造不了。

### 全程加密(sealed box,不靠 TLS)

**明文端点已移除,客户端只能走加密信封** `POST /api/v1/secure`,卡密等字段不再明文上线(即便 TLS 被授权用户拿自己的 mitmproxy 剥掉):

```
客户端: 内层 {op, code, device_id, ...} 用临时 X25519 ECDH 到服务器静态 X25519 公钥
        -> AES-GCM 加密 -> {epk, n, ct} 上线(卡密等全是密文)
服务器: 用静态私钥 ECDH 解开,分发到对应 op,回执同样封成 {n, ct} 密文
```

- 机密性 + 服务器认证一体:只有持服务器 X25519 私钥的一方能解请求/产生合法回执,中间人读不了也伪造不了(即便 TLS 被剥)。
- 服务器公钥两把都要 pin 进客户端:Ed25519(验签)+ X25519(信封),`GET /api/v1/pubkey` 返回 `public_key` 与 `enc_public_key`。
- 参考客户端已全程走 `/secure`;实测上线信封只有 `{epk,n,ct}`,卡密不出现在明文里。

### 心跳续验(封卡/解绑/过期中途生效)

只在启动时验一次,封了卡也得等下次启动才断。加**签名心跳**后,客户端运行期间按服务器下发的间隔周期性调用:

```
POST /api/v1/heartbeat  {code, device_id, nonce}
     每拍重新判定卡有效性(封禁/解绑/过期实时生效),有效则返回签名回执:
       {success, body, sig},  body = {valid, status, expires_at, ts, nonce, heartbeat}
       sig = Ed25519(server_priv, frame(HEARTBEAT_AAD, body))
```

客户端**验签 + 校验 nonce 回显 + 校验时间戳新鲜度**,并 **fail-closed**:网络被断、被篡改、被重放、或 `valid=false`,一律判为失效并停止运行。因此后台一封卡 / 解绑设备 / 卡过期,**下一拍心跳即断**,不用等重启。

- **间隔随机**:服务器每拍在 `[heartbeat_min, heartbeat_max]` 内随机选下次延迟,并**签名**放进回执 `next` 字段下发。客户端二进制里**没有固定间隔常数**可 pattern-match / patch,抬高逆向成本。范围在「站点设置」配(10–3600 秒);要"约每小时且抖动"设 `3000 / 3600`。
- 成功心跳不写日志(避免刷屏),失败心跳(封禁/解绑等)会记入验证日志。
- 参考客户端演示:`python -m examples.client --code <卡> --beats 6`(间隔由服务器随机下发)。

### 多应用隔离(一套后台管多个软件)

后台可管理多个 `Application`,每个软件独立卡池 + 独立 `K_payload`。卡属于哪个应用,`/session` 就下发哪个应用的密钥——**A 软件的卡解不开 B 软件的核心**(实测:换应用的卡去解另一应用的 `core.enc` 得到 `InvalidTag`)。

- 「应用」页创建软件,拿到它的 `app_key`;生成卡密时选所属应用。
- 服务器 Ed25519 签名公钥**全局共用**一把(客户端 pin 它);隔离体现在 per-app 的 `K_payload` 与卡归属。
- 轮换某应用的 `K_payload` 后,该应用的核心需重新加密分发(其它应用不受影响)。

### 工作流

```bash
# 1. 列出应用 / 看某应用的 K_payload 指纹 + 服务器公钥(公钥 pin 进客户端)
python -m tools.protect list-apps
python -m tools.protect keyinfo --app <app_key>

# 2. 用该应用的密钥把软件核心加密成 .enc,随程序分发
python -m tools.protect encrypt --app <app_key> examples/core_plain.py examples/core.enc

# 3. 参考客户端:取机器码 -> 握手授权 -> 解出密钥 -> 解密执行 core.enc
python -m examples.client --code <该应用的卡密>
```

- 服务器密钥在首启生成于 `data/keys/`(`ed25519_priv.key` 签名钥、`payload.key` 即 K_payload),**已 gitignore,不入库**。
- 参考客户端是 Python,协议语言无关——真实 C/C++/C#/Delphi 客户端照上面 wire format 重写 2–6 步即可,机器码指纹按目标平台采集(Windows 用 MachineGuid+CPU+MAC)。
- 加壳(VMProtect/Themida)、反调试、反 dump 是**第二层**加固,叠在这套门控之上;单独用它们而不做密钥门控仍可爆破。
- 诚实的边界:被授权用户在自己机器上能 dump 出解密后的核心——这是任何客户端解密方案的固有上限。要更强,把最关键逻辑放服务器端执行(客户端拿不到就破不了)。

## 卡密状态机

```
unused ──activate──> active ──(到期)──> expired
   │                   │
   │                   └──(点数用尽)──> used_up
   └───────── banned <── (任意状态可被后台封禁; 解封回到 active/unused)
reset: 解绑全部设备 + 回到 unused
```

- `unused/active/banned` 为存储状态;`expired/used_up` 由到期时间 / 剩余点数实时推导。
- 每张卡可绑定 `max_devices` 台设备;达上限后新设备激活被拒,需后台解绑释放。

## 目录结构

```
app/
  main.py            应用装配 + lifespan(建表 / bootstrap admin / 生成密钥)
  config.py          配置(env 覆盖)
  database.py        engine / session / Base
  security.py        pbkdf2 口令散列 + 随机码生成
  crypto.py          Ed25519 签名 / X25519 ECDH / AES-GCM / HKDF(客户端保护)
  deps.py            会话鉴权依赖(current_admin / require_super)
  templating.py      Jinja2 + 过滤器 + flash
  models/            Admin / Application / CardType / Card / Device / AuthLog / AuditLog / Setting
  services/          applications / cards / devices / verify / settings / audit
  routers/           auth / dashboard / applications / cards / devices / logs / system / api
  templates/  static/
tools/protect.py     用 K_payload 加/解密软件核心(build 期)
examples/client.py   参考客户端(机器码 -> 握手 -> 解密执行 core.enc)
scripts/seed.py      演示数据
tests/               test_flow(API+登录) / test_crypto(握手+载荷)
```

```bash
python -m pytest -q          # 运行测试
```

## 配置项(env / .env)

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `APP_NAME` | 卡密授权管理后台 | 站点名 |
| `SECRET_KEY` | dev 值 | 会话签名密钥,生产务必改 |
| `DATABASE_URL` | `sqlite:///data/app.db` | 可切 `mysql+pymysql://...`(需 `pip install pymysql`) |
| `DEFAULT_ADMIN` / `DEFAULT_ADMIN_PWD` | admin / admin888 | 首启超管 |
| `PWD_ITERATIONS` | 200000 | pbkdf2 迭代次数 |

## 已知限制

- 未内置 CSRF token 与接口限流;`SECRET_KEY` 默认值仅供本地,部署前必须替换。
- 设备并发绑定的原子性依赖数据库;SQLite 下写串行化,MySQL 需按需加行锁。
