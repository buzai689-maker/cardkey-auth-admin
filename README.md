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

被授权的客户端用**卡密 + 机器码(device_id)**调用。请求 / 响应均为 JSON,返回结构:
`{"success": bool, "message": str, "data": {...} | null}`。

```bash
# 激活并绑定当前设备(首次使用时开始计时 / 绑定)
curl -X POST http://127.0.0.1:8000/api/v1/activate \
  -H "Content-Type: application/json" \
  -d '{"code":"DAY-XXXX-XXXX-XXXX","device_id":"MACHINE-CODE-001","device_name":"PC-01"}'

# 心跳 / 登录校验(需该设备已绑定)
curl -X POST http://127.0.0.1:8000/api/v1/verify \
  -H "Content-Type: application/json" \
  -d '{"code":"DAY-XXXX-XXXX-XXXX","device_id":"MACHINE-CODE-001"}'

# 自助解绑(需在站点设置里开启 allow_self_unbind)
curl -X POST http://127.0.0.1:8000/api/v1/unbind \
  -H "Content-Type: application/json" \
  -d '{"code":"DAY-XXXX-XXXX-XXXX","device_id":"MACHINE-CODE-001"}'
```

`data` 字段:`status` / `type` / `activated_at` / `expires_at` / `max_devices` / `bound_devices` / `remaining_count`。

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
  main.py            应用装配 + lifespan(建表 / bootstrap admin)
  config.py          配置(env 覆盖)
  database.py        engine / session / Base
  security.py        pbkdf2 口令散列 + 随机码生成
  deps.py            会话鉴权依赖(current_admin / require_super)
  templating.py      Jinja2 + 过滤器 + flash
  models/            Admin / CardType / Card / Device / AuthLog / AuditLog / Setting
  services/          cards / devices / verify / settings / audit
  routers/           auth / dashboard / cardtypes / cards / devices / logs / system / api
  templates/  static/
scripts/seed.py      演示数据
tests/test_flow.py   API + 登录流程测试
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
