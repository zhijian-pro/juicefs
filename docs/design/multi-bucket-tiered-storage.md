# 多桶分层存储设计：sliceID 记桶引用 + Attr 记 tier 策略

> 状态：**ADR-1 四项 + 开放问题 8 项决策已确认（§11/§14），位布局已冻结**；
> 第二轮对抗性评审条款已合入正文。进入 Phase 1 的剩余前置 = §9 S0 条款
> 实现级闭环（唯一未决：§11.4 retire 参数，Phase 2 细化时定）
> 分支：`multi-bucket-design`
> 前置阅读：现有单桶分层实现（`Attr.Tier` + `Format.Tiers` + `TierKey` ctx 链路）
> 评审记录：本文档 §9/§12-14；外部评审 `workdoc/juicefs/评审记录/multi-bucket-tiered-storage-adversarial-review.md`

## 目录

- [1. 背景与目标](#1-背景与目标)
- [2. 方案总览](#2-方案总览)
  - [2.1 核心结构](#21-核心结构)
  - [2.2 设计原则：信息-载体匹配](#22-设计原则信息-载体匹配)
- [3. 元数据设计](#3-元数据设计)
  - [3.1 sliceID 位布局（永久契约，一次定死）](#31-sliceid-位布局永久契约一次定死)
  - [3.2 Format 扩展](#32-format-扩展)
  - [3.3 Attr.Tier 语义](#33-attrtier-语义)
  - [3.4 不变量](#34-不变量)
- [4. 存储层](#4-存储层)
- [5. 场景流程、伪代码与多客户端并发分析](#5-场景流程伪代码与多客户端并发分析)
  - [5.1 写入](#51-写入)
  - [5.2 writeback / staging](#52-writeback--staging)
  - [5.3 读取](#53-读取)
  - [5.4 迁移](#54-迁移)（含无锁删除安全原则、双向迁移推演、硬链接/软链接迁移语义）
  - [5.5 Clone](#55-clone)（含 clone × 软链接/硬链接、Tier 继承决策）
  - [5.6 Compact](#56-compact)
  - [5.7 GC](#57-gc)
  - [5.8 Fsck](#58-fsck)
  - [5.9 异常中断与崩溃恢复](#59-异常中断与崩溃恢复)
  - [5.10 文件类型语义](#510-文件类型语义)
- [6. 多客户端并发矩阵（汇总）](#6-多客户端并发矩阵汇总)
- [7. 兼容性](#7-兼容性)
  - [7.1 版本门控（两阶段激活）](#71-版本门控两阶段激活)
  - [7.2 dump/load](#72-dumpload)
  - [7.3 回滚（软单向门）](#73-回滚软单向门)
- [8. 安全](#8-安全)
- [9. 评审必须项（两轮合并，Must-fix）](#9-评审必须项两轮合并must-fix)
- [10. 分期实施](#10-分期实施)
- [11. 开放问题（决策进展）](#11-开放问题决策进展)
- [12. 成本模型与故障域（第二轮评审新增）](#12-成本模型与故障域第二轮评审新增)
- [13. 备选方案对比（Alternatives）](#13-备选方案对比alternatives)
- [14. 决策变更记录（ADR-1，已确认）](#14-决策变更记录adr-1已确认)

## 1. 背景与目标

现有分层存储是**文件级、单桶**的：`Attr.Tier`（inode 属性）决定写入对象的
storage class，对象 key 只由 sliceID 派生，读取无需感知 tier。

业务需求：

1. 文件数据可放入**不同 bucket**（支持跨账号 / 跨云），文件级粒度；
2. 支持**手动调整**（`juicefs tier set`）与**自动规则调整**（目录继承 + 后台迁移）；
3. 不同于 `Shards`（静态 key 哈希、同构桶、不可调整）；
4. gc / fsck / info / destroy 等配套工具全部兼容。

## 2. 方案总览

### 2.1 核心结构

```text
用户/策略层:  Attr.Tier (uint8, inode 属性, 可变)
                 │  open 时解析一次并快照
                 ▼
             Format.Tiers[tierID] = {BucketRef, Sc}      ← 半可变策略指针（ADR-1.1）：
                 │                                          Sc 可改；BucketRef 创建后不可改，
                 ▼                                          换桶 = 新建 tier + 显式迁移
数据路由层:  sliceID 高位 = BucketRef ──▶ Format.Buckets[ref] = {Storage, Endpoint,
                                            AK/SK(加密), State}
                                            ← 身份（ref↔逻辑容器）恒定；地址/凭证可变；
                                              ref 只增不复用；下线走状态机（§3.2）
```

### 2.2 设计原则：信息-载体匹配

写一个 slice 需要两个信息，它们的生命周期需求不同，因此载体不同：

| 信息 | 读取需要吗 | 事后可改吗 | 载体 |
|---|---|---|---|
| bucket（去哪） | **永久需要**（找不到桶就读不到） | 改 = 搬数据 | **sliceID 高位**（永久，随身份传播） |
| sc（怎么存） | 不需要 | 同 key Copy 即可改 | **ctx 传一程**（瞬时），意图留 Attr/Tiers |

由此获得的结构性性质（对照代码验证）：

- 读 / 删除 / GC **自路由**：所有只拿 `(id, size)` 的路径（`NewReader`、
  `DeleteSlice` 消息、gc key 反解）从 id 位直接得到桶，零 plumbing；
- clone / `copy_file_range` 共享 slice 天然正确：id 自描述位置，与引用者的
  Attr 无关；
- compact 自动归拢：compact 以 `attr.Tier` 写新对象（现状 `base.go` 已实现），
  新 id 打新桶位，旧 slice 走 ref 清理；
- 存量数据零迁移：现有 id 高位全 0 = 默认桶（ref 0）。

## 3. 元数据设计

### 3.1 sliceID 位布局（永久契约，一次定死）

```text
bit 63    : 恒 0（PostgreSQL BIGINT 为有符号；nextChunk 计数器为 int64）
bit 60-62 : 保留，恒 0（未来：格式版本/加密纪元等）
bit 56-59 : BucketRef（4 位，最多 16 个桶注册表项）
bit 0-55  : rawID（nextChunk 计数器域，≈7.2e16，按每秒百万 slice 可用 2000+ 年）
```

```go
const (
    bucketRefShift = 56
    bucketRefBits  = 4
    bucketRefMask  = uint64(1<<bucketRefBits-1) << bucketRefShift // bit 56-59
    reservedMask   = uint64(0xF) << 60                            // bit 60-63，恒 0
    rawIDMax       = uint64(1) << bucketRefShift
)

func stampID(rawID uint64, ref uint8) (uint64, error) {
    if rawID >= rawIDMax || ref >= 1<<bucketRefBits {
        return 0, fmt.Errorf("slice id space exhausted or invalid ref: raw=%d ref=%d", rawID, ref)
    }
    return rawID | uint64(ref)<<bucketRefShift, nil
}
func bucketRefOf(id uint64) uint8 { return uint8(id >> bucketRefShift & (1<<bucketRefBits - 1)) }
func rawIDOf(id uint64) uint64    { return id & (rawIDMax - 1) }
func validateID(id uint64) error {
    if id&reservedMask != 0 { return ErrReservedBits } // 持久输入用显式错误，禁止 panic
    return nil
}
```

**位域测试向量表**（实现必须包含此表的单元测试）：

| id (hex) | rawID | ref | 合法性 |
|---|---|---|---|
| `0x0000_0000_0000_0001` | 1 | 0 | 合法（存量数据形态） |
| `0x0100_0000_0000_0001` | 1 | 1 | 合法 |
| `0x0F00_0000_0000_002A` | 42 | 15 | 合法 |
| `0x1000_0000_0000_0001` | — | — | 非法（bit 60 保留位被置位） |
| `0x8000_0000_0000_0001` | — | — | 非法（bit 63，PG 有符号溢出） |

> 修正记录：初版 `rawIDOf` 掩码 `0xE0<<56` 漏清 bit 60（两轮对抗性评审均命中）。
> 现以 `rawIDMax-1` 取低位从构造上消除整类错误；一切来自持久介质的输入
> （dump/load、对象 key 解析、计数器）校验失败返回显式错误，panic 仅允许用于
> 进程内已验证的不变量。

守恒校验（三处）：

1. `NewSlice`：分配出的 rawID 越界 → 拒绝并报警（理论不可达）；
2. `format` / `load`：`nextChunk` 计数器必须 < `rawIDMax`，否则显式拒绝；
3. dump 载入：出现的 BucketRef 必须存在于目标卷注册表，否则显式拒绝
   （不静默丢失，AGENTS.md 红线）。

### 3.2 Format 扩展

```go
type Bucket struct {
    Ref       uint8  // 注册表下标：只增、永不复用（终身预算，见下）
    // 身份（不可变）：ref ↔ 逻辑容器的绑定关系。同一物理桶严禁注册为两个 ref
    //（INV-1 别名互删风险，S0-1）；config 时对规范化 endpoint 指纹做尽力检测。
    // 地址与凭证（可变）：运维现实要求 endpoint 可换（内外网切换、云厂商域名
    // 弃用、自建存储迁址）、凭证可轮换。路由查注册表实时内容，地址变更对新旧
    // 句柄同时生效且安全——只要仍指向同一逻辑容器。
    Storage   string
    Endpoint  string
    AccessKey string // 可空（推荐）：空 = 本地凭证链（按 ref 命名的环境变量 /
    SecretKey string // 凭证文件 / instance role），凭证不入 meta（决策 #6）；
                     // 非空 = 信封便利模式（落库加密，防护等级见 §8）
    State     string // active → draining → sealed → retired（状态机见下）
}

type Format struct {
    // ...现有字段...
    Buckets map[uint8]Bucket // ref 1-15；ref 0 由旧字段虚拟合成（见下）
    Tiers   map[uint8]Tier   // 现有结构扩展
}

type Tier struct {
    ID        uint8
    Sc        string // storage class：可修改（成本操作，不影响正确性）
    BucketRef uint8  // 指向 Buckets；0 = 默认桶。创建后不可修改（ADR-1.1 半可变）：
                     // 换桶 = 新建 tier + 显式迁移。消除"改指针批量重定向"的
                     // 误操作爆炸半径（百万文件瞬间 unconverged + 自动搬数据账单）、
                     // 审计不可追溯（Format 无定义变更历史）与多客户端传播窗口混桶
}
```

**桶生命周期状态机**（第二轮评审 H-2：`active|retired` 两态无法关闭旧句柄
并发写入的窗口）：

```text
active   : 正常读写
draining : Tiers 不得再指向该 ref；禁止新 open 快照该桶；存量句柄可继续写
sealed   : 禁止任何新 PUT 与新元数据引用；等待旧句柄 / staging 回放 / 迁移
           reservation 全部排空（按 session 枚举验证）；存量数据仍可读
retired  : 全量扫描零引用后进入；仅保留只读+列举供 gc 清残；凭证永久失效时
           转 tombstone（放弃列举，残留对象按最后一次清单人工处理，
           gc/fsck 跳过并告警而非挂死）
```

- **ref 0 的唯一权威来源**：ref 0 永远由现有 `Storage/Bucket/AccessKey/
  SecretKey` 字段**虚拟合成，不写入 Buckets map**。load/config 时若发现
  ref 0 实体项 → 显式拒绝（消除双重权威来源，第二轮评审 Medium）。

**注册查重协议**（S0-1 检测手段，从 endpoint 指纹升级为三层探测）：

```text
注册新桶 ref=N：
1. 指纹快筛：规范化 endpoint（scheme/host/bucket 名）比对，免费先挡低级重复
2. 主动探针：向新桶写 <name>/probe_<random> → 对所有已注册桶 Head 同 key
   → 任一可见 = 同一物理桶（写入透过两个地址可见）→ 拒绝；随后删除探针。
   不受地址形态影响（内外网/CNAME/IP/path-style 全覆盖）
3. 持久身份标记：写 <name>/bucket_id = {volumeUUID, ref, 注册时间}
   → 注册时新桶已存在本卷 bucket_id（其他 ref）= 别名或既有桶的拷贝 → 拒绝
     （主动探针抓不到"注册前拷贝"，标记可以）
   → gc/fsck 每轮顺带复核 marker↔ref 一致性 = 运行期持续检测，
     覆盖弱一致后端注册时的漏检
```
- **16 个 ref 是卷的终身注册预算，不是并存桶数**：ref 不复用 ⇒ 每次 retire
  永久消耗名额。endpoint 可变性已消除"换地址烧名额"这一主要消耗源；剩余
  消耗事件 = 真实的新桶启用与桶弃用。产品决策必须以"卷生命周期内的桶变更
  事件总数"评估位宽（§11 开放问题 1，§14 ADR 待确认项）。
- `Format.Encrypt/Decrypt` **必须**扩展遍历 `Buckets[].AccessKey/SecretKey`
  （现状只处理三个固定字段）；三引擎 dump 的 `keepSecret` 脱敏同步扩展。

### 3.3 Attr.Tier 语义

编码不变（Attr 尾部可选字节 + SQL `tier_id` 列），语义从"存储类"升级为
"策略层级指针"。继承逻辑不变（mknod 继承父目录）。

**意图 vs 现实**：`Attr.Tier` 表达"该文件的数据应该在哪"（意图）；slice 的
桶位表达"实际在哪"（现实）。二者允许暂时不一致（迁移中 / 中断后），
读以 slice 为准、写以 Attr 为准，`tier status` / fsck 负责度量与收敛。

### 3.4 不变量

- **INV-1（驻留不变量与删除纪律）**：id 位声明 ref=N 的对象只应存在于桶 N。
  错位对象的处置分三态：**死的**（id 不在 meta）由泄露规则直接删（与桶无关）；
  **活的**走 gc 内置的正证据修复协议（§5.7 `healMisplaced`：copy-verify-delete，
  删除只发生在正面确认正确桶有完好副本之后）；**尺寸不符/heal 失败**的只报告
  留人工。**禁止基于负证据（404/单信号"位≠桶"）的删除**——"错位"信号无法
  区分"多余拷贝"与"bug 写错地方的唯一真身"，而后者经 heal 可完整恢复
  （错位副本对读者本就不可见，heal 同时修复读故障）。错位写入本身由两道
  结构性防线预防（§4：PUT 点自断言 + 身份标记复核）。
- **INV-2（可读）**：meta 中存在的 slice，其 id 位声明的桶中必须有**全部
  block**（迁移保留期内的旧副本读取例外，见 INV-6）。
- **INV-3（注册表身份）**：ref ↔ 逻辑容器绑定不可变；ref 永不复用；同一物理
  桶严禁多 ref 注册（注册时三层探测：指纹快筛 + 主动写探针 + 持久身份标记，
  见 §3.2；运行期由 gc/fsck 复核身份标记持续检测）；下线必须走完整
  状态机（§3.2），"零引用扫描"单独不构成下线证明。
- **INV-4（ID 域）**：rawID < 2^56；bit 60-63 恒 0；持久输入校验失败返回
  显式错误。
- **INV-5（迁移在途双重保护）**：迁移新对象在 meta 提交前必须受两道保护：
  ① **migration reservation**（首个 PUT 前在 meta 登记、带过期时间，gc 视为
  pending-live——首道防线，机制性）；② gc mtime 窗口（默认 1h，
  `JFS_GC_SKIPPEDTIME` 有强制安全下限——第二道防线，缓冲性）。
  **窗口是缓冲不是正确性边界**（第二轮评审 S0-2：纯窗口方案存在
  check-then-commit TOCTOU，且窗口可被环境变量缩小）。
- **INV-6（迁移保留期）**：迁移导致 ref 归零的旧对象必须进入**独立保留队列**，
  保留期 = max(TrashDays, 迁移最小保留期 24h)，**不随 TrashDays=0 立即物理
  删除**（现状 compact 在 TrashDays=0 时立即删，迁移不得沿用）；迁移事务
  提交后须 Head 验证新对象存在，缺失则趁旧副本仍在保留期内重拷自愈。
- **INV-7（副本安全不变量，删除体系的总纲）**：对任一**活着的**对象
  （id 被 meta 引用），目标端 = id 位声明的桶。
  **安全态** = 目标端持有完好副本（其余桶副本为允许的冗余）。操作纪律：
  - D1. 任何删除的后置条件 = 删除后仍处安全态 ⇔ 删除前正面验证目标端
    副本完好，且被删的不是它；
  - D2. 非安全态（唯一副本在错位桶）：删除**全面禁止**，唯一合法操作 =
    向目标端收敛拷贝；
  - D3. 安全态下的冗余副本可删。
  推论：**单副本必在目标端；双副本至少一个在目标端**。逐操作保持性：
  写入经 PUT 自断言直落目标端；heal 全程副本数 ≥1 且删除仅在回读验证后
  （§5.7）；gc 泄露删除仅作用于死对象；迁移不触碰同 key、旧 id 变死后才删
  （INV-6 队列）。INV-7 不承诺违规态不出现（预防靠 §4 两道防线），承诺
  **任何操作不制造/加深违规态，heal 单调收敛回安全态**。基于负证据
  （404/单信号）的删除违反 D2，全域禁止。

## 4. 存储层

```go
// 替换现有 initStorageTiers 装饰器，构建于 Buckets 之上（与 Tiers 解耦）
type bucketRouter struct {
    stores [16]atomic.Pointer[ObjectStorage] // 凭证轮换/endpoint 变更时原子换实例
}
```

**Key namespace 路由表**（第二轮评审 S0-4：同一 storage 还承载非 chunk
对象——`meta/*` 元数据自动备份 vfs/backup.go:134、`testing/*` 连通性测试
cmd/format.go:377、`juicefs_uuid`——对任意 key 做 parseSliceID 是错误的）：

| key 前缀 | 路由 |
|---|---|
| `chunks/...` | 解析 slice id → 按高位 ref 路由；**解析失败 = 显式错误，绝不回退 ref 0** |
| `meta/`、`testing/`、`juicefs_uuid` 等控制对象 | 恒 ref 0（canonical 桶） |

**完整 ObjectStorage 契约**（Phase 1 设计细化项）：router 必须定义全接口
语义——`List`/multipart（`CreateMultipartUpload/ListUploads/...`）/`Limits`/
`Copy`/`Shutdown`：`Copy` 仅允许同 ref（跨 ref 归迁移原语）；multipart 按
key 路由到单桶；`Limits` 取各桶交集；`Shutdown` 广播；任何方法的部分失败
必须上抛而非吞掉。

**gc/fsck/destroy 不做全局 k 路归并**（第二轮评审 H-5）：逐桶独立扫描、
独立 checkpoint、独立成功/失败报告——现状 sharding 归并对单桶 List 错误
**无限重试**（sharding.go:147-152）且任一子桶失败即整体失败，一个 retired
桶凭证过期会挂死全部工具。没有任何调用者真正需要全局有序流。

**错位写入的两道结构性防线**：

1. **PUT 点自断言**：每个 per-ref storage 实例在 Put 时校验
   `bucketRefOf(parseSliceID(key)) == 自身 ref`，不匹配拒写（`ErrMisroute`）。
   key 自带真相 ⇒ 上游路由表过期、reload 竞态、映射 bug 整类被挡在落盘前。
   唯一漏网的"打标本身打错"产生的是**自洽数据**（key/meta/落桶三者一致，
   可读、可迁移收敛），不产生错位、不丢数据；
2. **身份标记复核**：客户端初始化/Reload 每个桶实例时校验 `bucket_id`
   标记与自身 ref 一致（§3.2），不一致拒绝启用该桶——防"endpoint 改错
   指向别的物理桶"这一错位来源。

装饰器顺序：`encrypted( bucketRouter{ ref→prefix(blob) } )`。
卷级 `Compression`/`EncryptKey` 全局统一，跨桶数据格式一致。

**Reload 拆分**（现状对任何 Tiers 变化整体重建 storage；且 mount.go:486 的
`holder.ObjectStorage = newBlob` 是**非原子字段赋值——既有数据竞争，列为
本设计的前置修复**）：

- Buckets 新增 / 凭证或地址变更 → 只重建对应 ref 的 storage 实例（原子交换）；
- Tiers 变更 → 只替换策略映射，**不触碰 router**（在写句柄不受影响的根基）。

## 5. 场景流程、伪代码与多客户端并发分析

以下伪代码中：`C1/C2/...` 表示不同客户端；`meta.Txn` 表示引擎事务
（Redis WATCH+MULTI / SQL 事务 / TKV CAS），三引擎语义必须一致。

### 5.1 写入

```go
// open：解析并快照（隔离后续一切配置/attr 变更）
func Open(inode) *handle {
    attr := meta.GetAttr(inode)
    def, ok := format.Tiers[attr.Tier]
    if !ok {                       // Format 传播延迟（见并发分析 W-4）
        format = meta.ReloadFormat()
        def, ok = format.Tiers[attr.Tier]
        if !ok { return EIO }      // 绝不静默回退默认桶
    }
    h := &handle{inode: inode, bucketRef: def.BucketRef, sc: def.Sc}
    return h
}

// 写数据块
func (s *sliceWriter) flush() {
    rawID := meta.NewSlice()                     // 4096 批分配，客户端本地
    s.id = stampID(rawID, s.h.bucketRef)         // ← 打标点：首个 PUT 之前
    for indx, block := range s.blocks {
        ctx := WithValue(ctx, PlacementKey{}, placement{s.h.bucketRef, s.h.sc})
        router.Put(ctx, key(s.id, indx, len), block) // 桶由 key 中 id 位决定
    }
    meta.Write(inode, chunkIdx, slice{id: s.id, ...}) // meta 提交（含 sliceRef 登记）
}
```

**Placement snapshot 与 TierKey 契约**（第二轮评审 H-1）：现状 `TierKey` ctx
只接受 `uint8` tier id，且未知值**静默回退 tiers[0]**
（object_storage.go `getRuntimeTier`）——与本设计"绝不静默落错"原则直接冲突。
因此**不重载 TierKey 的类型语义**，新增独立的
`PlacementKey{BucketRef uint8; Sc string}` ctx 类型；对象层收到未知/缺失
placement 一律显式报错，不回退默认值。

**多客户端并发分析（写）**

| 编号 | 场景 | 行为与结论 |
|---|---|---|
| W-1 | C1、C2 并发写同一文件（各自 open 快照的 tier 不同，例如中间隔了 tier set） | 各自的 slice 打各自的桶位，**都自描述、都可读**。文件暂时混桶，由迁移/compact 收敛。POSIX 对并发写本就不保证内容顺序，此处不引入新语义。 |
| W-2 | 写入 与 `tier set`（SetAttr 翻转）并发 | 已 open 句柄继续写旧桶（快照），落下的是"旧位但正确"的数据；迁移工具重扫收敛（见 5.4）。**不存在错位数据**（对比文件级方案：attr 已新、数据在旧桶且无从判定）。 |
| W-3 | 写入 与 tier 定义变更并发 | ADR-1.1 后 tier 的 BucketRef **不可改**，此场景只剩改 Sc：句柄用 open 快照的 sc，新 open 用新值——sc 漂移无害（不影响可读性），fsck 对账。原"改 BucketRef 并发"场景已被半可变决策**结构性消除**。 |
| W-4 | C1 刚 `config` 加桶并设 tier，C2 的 Format 缓存尚未刷新（OnReload 周期），C2 打开 attr.Tier=新 tier 的文件 | C2 解析失败 → 强制 reload Format 重试 → 仍失败则 **EIO**。规则：宁可失败，绝不静默落错桶。 |
| W-5 | ID 批分配竞争 | 各客户端独立获取 4096 大小的 rawID 批（现状 `incrCounter("nextChunk")`），打标是本地位或，无新增竞争点。 |

### 5.2 writeback / staging

```go
func (s *wSlice) upload(indx) {
    key := key(s.id, indx, blen)          // 打标 id 已在 key 中 → 桶信息已持久化在文件名里
    if writeback {
        bcache.stage(key, data, footer{bucketRef: s.h.bucketRef, sc: s.h.sc})
        // 上传（立即或延迟）：
        //   桶：key 中 id 位自路由（重启回放 scanStaging 同样成立）
        //   sc：读 footer（写入时刻的意图快照，不受 tier 定义后续变更影响）
    }
}
```

**staging footer schema 迁移**（第二轮评审 H-1）：现状 footer 只有
`Tier uint8`（disk_cache_file.go），回放时二次解析可变的 Tiers 定义——与
快照原则冲突。新 schema 为 `{BucketRef uint8, Sc string}`（msgpack 向后
兼容：读到只含 Tier 字段的旧 footer 时，按启动时 Format 解析一次并告警；
未知 tier → 该 staged 块报错滞留、人工处理，不静默回退）。

**并发分析（writeback）**

| 编号 | 场景 | 行为与结论 |
|---|---|---|
| S-1 | staged 未上传期间，其他客户端发起迁移 | 迁移对该 slice `Get(oldKey)` 得 404 → **本 slice 迁移失败、跳过，slice 记录不动**（id 仍指旧桶）。staged 块稍后上传到旧桶 = id 声明桶，一致。下轮迁移收敛。只影响收敛速度，无正确性问题。 |
| S-2 | 客户端崩溃重启 | `scanStaging` 重登记，key 含桶位 → 回放自路由。footer 的 sc 快照仍有效。 |
| S-3 | staged 期间 tier 定义的 sc 被改 | 回放用 footer 快照的旧 sc。属可接受漂移（sc 不影响可读性），fsck 对账。 |

### 5.3 读取

```go
func (s *rSlice) ReadAt(page, off) {
    // 1. 本地缓存（key 含 id → 缓存组织不变）
    if data := bcache.load(key); ok { return data }
    // 2. 对象存储：router 从 key 中 id 位选桶（零新增 plumbing）
    data, err := router.Get(ctx, key, off, len)
    if err == ENOENT {
        // 与现状 compact 相同的失效语义：持有过期 slice 列表
        return err // 上层 vfs 使旧 chunk 视图失效并重取 slice 列表后重试
    }
}
```

**并发分析（读）**

| 编号 | 场景 | 行为与结论 |
|---|---|---|
| R-1 | C1 读取中，C2 迁移了该文件 | C1 持旧 slice 列表：旧 id 对象在**延迟删除窗口**内仍可读（迁移清理走 sliceRef→delslices，同 compact 旧数据的清理节奏）。窗口过后读到 ENOENT → 复用 compact 既有的"失效重读 slice 列表"路径，取到新 id 后从新桶读。**无新增重试机制**。 |
| R-2 | 读归档（Glacier）对象 | 与现状一致：直接读、失败报错、用户 `tier restore` 解冻。restore 按 id 位自路由到正确桶。 |
| R-3 | 读 与 桶凭证轮换并发 | router 以 `atomic.Pointer` 交换实例；在途请求用旧实例完成（旧凭证吊销前完成轮换是运维时序要求，文档注明）。 |

### 5.4 迁移

三种操作，成本递减：

```text
op-A 搬桶（目标 tier 的 BucketRef 不同）: 数据拷贝 + slice 重写   —— 最贵
op-B 改 sc（同桶不同 tier，或改文件 attr）: SetAttr + 同 key Copy —— 便宜（现状 tier set 路径）
op-C 改 tier 定义的 Sc 字段              : 纯 Format 变更          —— 免费（批量成本意图变更，
                                            不影响正确性；BucketRef 不可改，ADR-1.1）
```

**op-A 伪代码（核心，已并入第二轮评审修订：reservation / block manifest /
ref 计数约定 / 共享去重 / 保留队列 / Head 自愈）**：

```go
func migrateFile(inode, dstTier) error {
    // 1. 意图先行：CAS 翻转 Attr（并发迁移意图串行化的锚点）
    if !meta.SetAttrCAS(inode, expectTier=curTier, newTier=dstTier) {
        return ErrConflict // 另一个迁移已改意图，本工具退出
    }
    dst := format.Tiers[dstTier]
    dedup := map[uint64]uint64{}                  // 会话级 oldID→newID 共享去重（§5.5）

    for each chunk of inode {
        slices := meta.ReadChunk(inode, chunkIdx)
        for batch := range batches(slices, batchSize) {
            // 2. reservation：首个 PUT 之前登记（INV-5 首道防线，gc 视为 pending-live）
            resv := meta.AddReservation(inode, expire=2h)
            for s := range batch {
                if bucketRefOf(s.id) == dst.BucketRef { continue }  // 幂等：已在目标桶
                newID, seen := dedup[s.id]
                if !seen {
                    newID = stampID(meta.NewSlice(), dst.BucketRef) // 全新身份，永不碰撞
                    // 3. 完整 block manifest 复制 + 校验（S0-5）：
                    //    一个 slice 是多个 block 对象（key(id, indx, blockSize)），
                    //    必须全部复制并逐块校验 size/checksum 后才允许换 ID——
                    //    半拷贝 + 整体切换 = 文件不可读
                    for indx := range blockManifest(s) {
                        data, err := srcBlob.Get(key(s.id, indx, ...))
                        if err == ENOENT { skipSlice }              // S-1：staged 未上传，下轮再迁
                        dstBlob.Put(ctx{placement{dst.BucketRef, dst.Sc}}, key(newID, indx, ...), data)
                    }
                    verifyManifest(newID, s)                        // 逐块 Head 校验 size
                    resv.Add(newID)
                    dedup[s.id] = newID
                }
                rewrites = append(rewrites, {old: s.id, new: newID, entries: entriesOf(s)})
            }
            // 4. 每批立即提交（小批仍是好实践，但正确性由 reservation 保证而非窗口）
            err := meta.Txn(func(tx) {
                if tx.GetAttr(inode).Tier != dstTier { // 防乒乓：意图已被并发迁移改写
                    return ErrSuperseded               // 整个迁移终止，让位给新意图
                }
                cur := tx.ReadChunk(inode, chunkIdx)
                if !matchEntries(cur, rewrites) {      // 逐条目匹配（含同 id 多条目，H-3）
                    return ErrRetry                    // 整批重读重试（新对象由 reservation 过期后转孤儿）
                }
                tx.ReplaceSliceEntries(chunkIdx, rewrites) // 按条目位置等长替换，非按 id 全局替换
                for r := range rewrites {
                    // ref 计数遵守各引擎原生约定（H-3）：Redis 存储值 = refs-1，
                    // 新 id 首条目 HSet "0"，多条目每条 +1；SQL/TKV 按各自约定。
                    tx.InitOrIncrSliceRef(r.new, r.entries)
                    tx.DecrSliceRef(r.old, r.entries)
                    // 归零 → 进迁移保留队列（INV-6）：保留期 max(TrashDays, 24h)，
                    // 不随 TrashDays=0 立即物理删除
                }
                tx.ConsumeReservation(resv)
            })
            headVerify(rewrites.new) // 5. 提交后抽验（INV-6 自愈钩子）：新对象缺失
                                     //    → 旧副本仍在保留队列 → 立即重拷 + 修复
        }
    }
    // 6. 收敛检查：迁移期间的并发新写（W-2）可能又落了旧桶
    if !converged(inode, dst.BucketRef) { rescan(inode) } // 重扫直到收敛或达到重试上限
    return nil
}
```

> **CopyFileRange 同 id 多条目警示（H-3）**：同一 slice id 可在同一/相邻 chunk
> 出现多个条目（不同 off/len，redis.go:3260-3274 按条目 RPush 且逐条目 ref+1）。
> `ReplaceSliceEntries` 必须按**条目位置**替换并按条目数增减 ref；若按 id 全局
> 替换而 ref 只 ±1，会过量递减、**提前删除仍被 clone 引用的对象**。三引擎共享
> 测试必须包含"同 id 多条目 + clone 引用"向量。

**无锁对象层的删除安全原则**：对象存储没有锁与事务，因此本设计规定**对象层
永远不承载决策**——迁移工具没有"删除"步骤，删除只能是 meta 事务内 ref 归零
的延迟副作用。由此，"刚写入的对象被并发迁移删除"需要同时突破三道防线：
① 新对象 key 含全新 rawID（计数器原子分配、永不复用），无人知晓、无从同名
互删；② 解引用它的事务必须先"看见"它并已把数据以更新的身份复制走
（copy-then-swap 顺序）；③ 唯一不受事务保护的窗口（PUT 后、meta 提交前的
孤儿态）由 **migration reservation（机制，首道）+ gc mtime 窗口（缓冲，
第二道）** 双重保护——纯窗口方案已被第二轮评审证明不足（TOCTOU +
`JFS_GC_SKIPPEDTIME` 后门 + TrashDays=0 立即删旧副本的三重叠加存在真实
丢数据路径），reservation 与 INV-6 保留期把"约定"升级为"机制 + 自愈"。

**推演：双向并发迁移（原方案丢数据场景在 D 下的对照）**

原设计文档风险场景：A 做 bucket1→bucket2（拷贝完成、元数据已改、未删 b1
旧副本）；B 反向做 bucket2→bucket1（拷贝、改元数据、删 b2 副本）；随后 A
按其计划删除 b1 副本 ⇒ 数据在两个桶中都被删除。原方案以 ForbidOverwrite
（对象层条件写）堵漏。同一交错在本方案下：

```text
初始:  chunk = [s0(b1)]，ref(s0)=1
A:     Get s0@b1 → Put newA@b2
       txn{ s0→newA, ref(newA)=1, ref(s0)-1→0 }
       ⇒ s0@b1 进延迟删除（窗口内旧读者仍可读）
B:     读 chunk 见 newA(b2)，目标 b1
       Get newA@b2 → Put newB@b1        ← newB 是全新 key，≠ s0 的 key
       txn{ newA→newB, ref(newB)=1, ref(newA)-1→0 }
       ⇒ newA@b2 进延迟删除
A:     后续批次事务校验：chunk 已不含 A 要替换的 id → 失败
       且事务内 attr 校验 ≠ A 的目标 → ErrSuperseded，A 终止
       A 手中不存在"待删列表"——删除从来不是工具的动作

终态:  chunk = [newB(b1)]，全程每一时刻至少一份副本可读，零丢失
```

原方案丢数据的两个根因，本方案各废其一：**key 复用**（B 拷回 b1 用的是 s0
的同一个 key，A 的删除会命中 B 刚写的数据）→ 每跳全新 rawID，key 永不复用；
**删除是工具按既定计划执行的动作**（不校验当前元数据事实）→ 删除仅为已提交
事务中 ref 归零的延迟副作用，陈旧计划无法通过事务校验、即无法产生删除。
因此无需引入对象层条件写（ForbidOverwrite/If-None-Match）这一新依赖。

**并发分析（迁移）**

| 编号 | 场景 | 行为与结论 |
|---|---|---|
| M-1 | C1、C2 对同一文件并发 `tier set`（不同目标） | Attr CAS 串行化**意图翻转**，但注意：后发 CAS 以新的当前值为期望（expect=t2, set=t1）依然成功，故两个迁移的重写阶段**可以短暂同时活跃**。安全性不依赖互斥，而依赖：① 每份物理副本 id 唯一（新 rawID，key 永不复用，不存在同名互删）；② 删除不是工具的动作，只是事务内 ref 归零的延迟副作用——解引用一个 id 的事务必然已把数据以新身份复制走；③ **每批事务内校验 attr==本迁移目标**（伪代码 `ErrSuperseded`），后发意图使先发迁移在下一批立即终止，乒乓最多一批、只浪费不丢失。**原设计文档中"双向迁移互删所有副本"的场景结构性消失**。 |
| M-2 | 迁移 与 并发写同文件 | 写走 Attr 新值（open 晚于 CAS）或旧快照（open 早于 CAS，落旧桶）。后者由第 6 步重扫收敛；**重扫仍不净的（长期打开的写句柄）没有自动收敛保证**——compact 只处理 `len(compacted)≥2` 的 chunk（base.go:2865），顺序写规整文件与追加型文件永不触发。语义必须二分：**最终策略**（如实显示 unconverged，不声称完成）与**严格排空**（需 generation fence/短暂拒写，见 §9 H-2，能力后置）。 |
| M-3 | 迁移 与 compact 同 chunk | 两者都在事务内做 chunk 原位替换 → 乐观冲突，一方 `ErrRetry`。compact 产物已带新桶位（attr 已翻转）→ 迁移重读后发现位正确，跳过。无死锁、无丢失。 |
| M-4 | 迁移 与 clone | clone 在事务内复制 slice 引用并 ref+1。若 clone 先行：迁移 ref-1 后旧 id ref 仍 >0 → **不删旧对象**，clone 文件继续可读（代价：两桶各一份，与原设计文档"clone 变两份数据，可接受"结论一致）。若迁移先行：clone 拿到的已是新 id。引擎事务保证两者串行化。 |
| M-5 | 迁移 与 GC | **双重保护**（INV-5）：reservation 使 gc 将在途新对象视为 pending-live（机制）；mtime 窗口为第二道缓冲。窗口不可单独依赖：check-then-commit 存在 TOCTOU（检查后工具挂起 → gc 删 → 提交），`JFS_GC_SKIPPEDTIME` 可缩窗口，跨云慢链路/限流/长尾重试都可击穿时间假设。提交后 Head 抽验 + INV-6 保留期提供最后自愈。 |
| M-6 | 迁移工具自身多实例（如两台机器跑 `tier apply`） | 同 M-1，Attr CAS 天然互斥到文件粒度；目录级任务用分片（按 inode 取模）避免无谓冲突。**持久 Job 控制面（job id/lease/checkpoint/限速/进度）为 Phase 2 必需**（第二轮评审 H-6），进程内重扫不足以支撑 TB 级跨云迁移的断点与多实例协作。 |
| M-7 | 迁移 与 老客户端 | **修正（第二轮评审 S0-3 证伪初版表述）**：`CheckVersion` 只在挂载时 `Load(true)` 执行；已挂载老客户端心跳走 `Load(false)`，只查 MetaVersion/UUID、**不复查 MinClientVersion**（base.go:914-925），且会静默丢弃 Buckets 字段继续运行——老二进制无法 retrofit。**两阶段激活**（§7.1）：抬版本后必须扫描活跃会话的客户端版本清单，存在低版本会话则拒绝创建非 0 BucketRef 并列出待驱逐会话；启用后的新挂载由 Load(true) 拒绝。 |

**硬链接的迁移语义**：迁移的操作对象是 inode 而非路径，故 N 个链接**同时生效、
天然原子**——tier 在 inode 上只有一个值、slice 只有一组，不存在"链接间层级
分裂"或部分迁移的表达空间（同 chmod 的 inode 语义）。配套约定：

- 单路径 `tier set` 遇 `Nlink>1`：照迁 + 警告，`GetPaths`（Redis `p$inode`
  hash / SQL edge 反查 / TKV 同构）列出其他路径，告知影响面；
- `-r` 递归：树内按 readdir 的 inode 号去重（不去重也会因"位已是目标"幂等
  跳过）；存在树外链接时默认照迁 + 警告（同 `chmod -R` 语义），`tier apply`
  自动化场景提供 `--skip-external-hardlinks` 保守跳过；
- 想让不同链接不同层级：不可表达，逃生通道是先 `cp`/clone 断开共享再迁移
  （clone 路线按 M-4 物化新副本，成本可见）；
- 与 link/unlink 并发：`ln` 只加 dentry + nlink（不碰 Tier 与 chunk），与
  Attr CAS、批事务均无冲突；unlink 至 trash 后迁移可继续但无意义（工具可在
  批事务读 attr 时检测提前终止）；彻底删除则批事务校验失败终止，孤儿对象走
  gc（F-1 路径）。硬链接未给迁移增加新的正确性场景，只增加告知义务与递归
  策略开关。

**软链接的迁移语义**：链接本体无数据可迁（target 只是元数据字符串）。核心
约束：**meta 层工具无法忠实跟随软链接**——target 以挂载点命名空间解释（绝对
路径指向宿主机、相对路径依赖内核解析上下文），元数据层没有挂载点信息，按
"卷根相对"强行解析可能命中碰巧同名的卷内文件而**迁错数据**。现状 CLI 的
`m.Resolve` 逐分量 doLookup、完全不跟随（base.go Resolve），这是 meta 模式下
唯一正确的选择（与 W-4 "宁可失败不静默落错桶"同一原则）。约定：

- `tier set <symlink>`（meta 模式）：明确报告 "symlink has no data" 并退出
  （现状静默设置惰性 Tier 后返回成功，属误导，需修正）；
- 若未来支持挂载路径模式：显式参数经内核 `Stat` 跟随到目标（chmod 式语义，
  ELOOP/ENOENT 由内核处理），忠实跟随仅在该模式下可行；
- `-r` 递归与 `tier apply` 规则：**永不跟随**（防环、防越出子树、防"冷目录中
  的链接把热数据拖冷"的策略意外），计数报告跳过数；
- 链接自身的惰性 Tier 不更新，fsck/info 对软链接忽略 tier 字段；
- `ln -sfn` 重定向与迁移并发：迁移作用于解析时刻的目标 inode，与 chmod
  竞态同构，POSIX 常态。

### 5.5 Clone

```go
// clone 本身零改动：事务内复制 slice 引用 + sliceRef+1（现状机制）
// 共享的 id 自带桶位 ⇒ clone 文件读取自动路由到数据实际所在桶，
// 与 clone 文件自身的 Attr.Tier 无关（Attr 只决定它的新写入去哪）
func Clone(src, dst) {
    meta.Txn(func(tx) {
        for s := range srcSlices { tx.SliceRef(s.id, +1) }
        tx.CopyChunks(src, dst)
        tx.SetAttr(dst, inheritOrPreserve) // dst 的 Tier 按 clone 语义继承
    })
}
```

**并发分析（clone）**：见 M-4。补充：clone 后对 dst `tier set` → dst 的 slice
被重写为新 id（ref±1），src 引用的旧 id ref 仍 >0 不受影响 —— 每个文件的迁移
只动自己的引用，共享关系由 ref 计数精确表达。

**clone × 软链接**：clone 复制的是链接本身（symlink 表行 / `s$inode`，不解引
用），零 slice、零 ref 操作，与多桶完全正交；链接指向哪个桶的文件无关——路由
发生在打开目标文件时。

**clone × 硬链接（放大风险与缓解）**：现状 clone **打断硬链接**（`Nlink>1`
置 1，代码注释 `TODO: preserve hardlink`），树内同一 inode 的 N 个 dentry 克隆
为 N 个独立 inode，共享源 slices（各 ref+1）。多桶推演：读取全部正确（slice 位
自描述）；但对克隆树整体 `tier set -r` 时，N 个 inode 各自 mint 不同新 id ⇒
源 1 份数据物化为 **N 份副本**。缓解：迁移工具维护会话级 `oldID→newID` 映射，
批内遇已迁旧 id 直接在事务中替换为**同一个**新 id 并 `ref(new)+1`（不再
Get/Put），跨 inode 保留共享、物理仅拷一份；映射为工具内存态，崩溃丢失仅退化
为重新拷贝（放大不出错）。

**识别边界**：真硬链接可识别——树内按 readdir 的 inode 号去重，树外由
`Nlink>1` 提示、`GetPaths`（Redis `p$inode` parent hash / SQL edge 反查 /
TKV 同构）可列全部路径；被 clone 打断的"前硬链接"则 inode 层血缘**永久丢失、
不可识别**。但去重映射不依赖识别 inode 血缘——它按 slice id 工作，共享事实
在 slice 层永不丢失（即 sliceRef 本身），硬链接/clone/`copy_file_range` 各种
共享形态被统一覆盖。跨会话迁移共享者会因映射丢失而各拷一份（放大不出错）；
`tier apply` 批量场景可用 `ScanSlices` 预建 id→inodes 倒排，把共享者排入同一
会话（调度优化，不影响正确性）。

**clone 的 Tier 继承语义（显式决策）**：现状 clone 整行复制 node（含 Tier 列，
`PRESERVE_ATTR` 只控制 uid/gid/mode/时间），产物**继承源的 Tier** 而非目标父
目录——与 mknod 继承父目录不一致，但多桶下是正确选择：继承源 ⇒ 意图=现实
（数据本就共享在源桶），clone 保持零拷贝、不隐式欠一次物化；继承目标父目录则
clone 完成即"未收敛"，违背零拷贝初衷。**决策：维持继承源**；用户需要改层级时
显式 `tier set -r`，成本可见。

### 5.6 Compact

```go
// 现状代码几乎不变，仅新 id 打标
func compactChunk(inode, chunkIdx, tierID) {
    slices := readChunk(inode, chunkIdx)          // 可能混桶（迁移半途/历史写入）
    newRaw := meta.NewSlice()
    def := format.Tiers[tierID]                   // tierID 来自 attr（现状 base.go 逻辑）
    newID := stampID(newRaw, def.BucketRef)
    data := readAll(slices)                       // 逐 slice 自路由读取
    router.Put(ctx{sc: def.Sc}, key(newID, ...), data)
    meta.Txn(func(tx) {
        if chunkChanged { return ErrRetry }
        tx.ReplaceChunk(chunkIdx, slice{newID, ...})
        tx.SliceRef(newID, +1)
        for s := range slices { tx.SliceRef(s.id, -1) } // 归零者进 delslices，删除自路由
    })
}
```

**并发分析（compact）**：与迁移的冲突见 M-3；与写入的冲突为现状既有语义
（事务重试）。**compact 是机会性收敛器，不是保证**（第二轮评审修正）：仅当
chunk 内 `len(compacted) ≥ 2` 才触发（base.go:2865）——顺序写规整文件
（每 chunk 单 slice）与追加型文件永不 compact，其混桶状态只能靠重扫迁移
收敛。"免费收敛"仅对碎片化写入成立，M-2 的兜底表述已同步修正。

### 5.7 GC

```go
func gc() {
    window := max(configuredWindow, minSafeWindow)   // JFS_GC_SKIPPEDTIME 有强制安全下限
    liveIDs := meta.ScanSlices()                     // 打标 id 全集（opaque 透传）
    pending := meta.ListReservations()               // 迁移在途新 id：pending-live（INV-5）
    for ref, blob := range router.buckets {          // 逐桶独立扫描/独立 checkpoint/独立报告
        for obj := range blob.ListAll("chunks/") {   // 单桶失败只影响该桶，不挂死全局
            if obj.Mtime > now-window { skip }       // 第二道缓冲
            id, err := parseSliceID(obj.Key)
            if err != nil { report(UNPARSEABLE, obj); continue } // 不删
            switch {
            case pending.Contains(id):    skip                    // 首道防线
            case bucketRefOf(id) > maxKnownRef:
                report(UNKNOWN_REF, obj)             // 持有过期 Format 的 gc 保守跳过（G-5）
            case !liveIDs.Contains(id):
                delete(obj)                          // 泄露规则先行：死对象无论在哪个桶都清理
                                                     // （死的错桶副本自动被此规则覆盖，无需特判）
            case bucketRefOf(id) != ref:
                healMisplaced(ref, obj)              // 活着的错位对象：正证据修复协议（见下）
            }
        }
    }
    expireReservations()                             // 过期 reservation 的对象转常规孤儿，下轮清
}

// 活着的错位对象的删除闭环：正证据修复协议（copy-verify-delete），
// 是 INV-7 副本安全不变量的执行体。
// 前置事实：读取永远按 id 位路由到正确桶 Y，没有读者会访问错位桶 X 的
// 这个 key ⇒ 错位副本对读者不可见，其唯一价值是"恢复源"；若 Y 缺对象，
// 则读取此刻已在报错——heal 不只是清理，是修复线上故障。
// 纪律：删除只发生在【本轮正面确认 Y 有完好副本】之后，
// 绝不基于负证据（404/超时/限流误判）删除。
func healMisplaced(x ref, obj) {
    Y := bucketOf(idOf(obj))
    if obj.Size != expectedSizeFromKey(obj.Key) {
        report(CORRUPT, obj); return          // 尺寸不符的杂散对象：不传播、不删，留人工
    }
    if y, err := Y.Head(obj.Key); err == nil && y.Size == obj.Size {
        delete(X, obj)                        // 正证据①：Y 已有完好副本 → X 中是冗余，删
        return
    }
    copy(X → Y, obj)                          // 先修复：唯一副本搬到正确桶（读故障随之恢复）
    if verifyReadback(Y, obj) {               // 正证据②：回读确认
        delete(X, obj)                        // 此刻 Y 必然有 → 删 X，读者全程无感知
    }                                         // 任一步失败 → 零动作，幂等，下轮重试
}
// 并发迁移把该 id 换掉 → 对象转死 → 下轮泄露规则清理，与 heal 无冲突。
```

**并发分析（GC）**

| 编号 | 场景 | 行为与结论 |
|---|---|---|
| G-1 | gc 与 迁移并发 | 见 M-5：reservation（机制）+ 窗口（缓冲）双重保护；过期 reservation 的对象转常规孤儿下轮清理。 |
| G-2 | gc 与 写入并发 | 现状既有语义（PUT→meta 提交秒级窗口 << 窗口下限），多桶不改变假设。 |
| G-3 | 两个 gc 并发 | 删除幂等；逐桶扫描只读。与现状一致。 |
| G-4 | gc 与 桶 retire | retired 桶仍被扫描清残；零引用证明 = 状态机 sealed 排空 + 连续 N 轮 gc 零命中（缺一不可，见 §3.2）；凭证永久失效 → tombstone，gc 跳过并告警而非无限重试挂死。 |
| G-5 | gc 持有过期 Format（不认识新 ref） | id 高位 > 已知最大 ref → 保守跳过并报告，绝不按"错桶/孤儿"删除；处理前先强制 reload Format。 |

### 5.8 Fsck

```go
func fsck(inode) {
    attr := meta.GetAttr(inode)
    want := format.Tiers[attr.Tier]
    for s := range slicesOf(inode) {
        ref := bucketRefOf(s.id)
        obj, err := router.Head(key(s.id, ...))   // 自路由，无需猜桶
        switch {
        case err == ENOENT:
            report(BROKEN, s)                     // INV-2 违反：真丢块（同现状 fsck 语义）
        case ref != want.BucketRef:
            report(UNCONVERGED, s)                // 意图≠现实：非错误，建议 tier set 收敛
        case obj.StorageClass != want.Sc:
            report(SC_DRIFT, s)                   // 漂移：--repair 触发同 key Copy 修正
        }
    }
}
```

**并发分析（fsck）**：fsck 与迁移并发时会看到 UNCONVERGED 中间态——按"意图 vs
现实"语义如实报告而非报错；`--repair` 的修复动作复用迁移原语（含 Attr CAS），
与在跑的迁移互斥。

### 5.9 异常中断与崩溃恢复

| 编号 | 中断点 | 落到的状态 | 恢复方式 |
|---|---|---|---|
| F-1 | 迁移：PUT 新对象后、事务提交前崩溃 | 新对象成孤儿（meta 无该 id） | gc 按"id 不在 meta"清理；重跑迁移分配新 id，幂等 |
| F-2 | 迁移：部分批已提交后崩溃 | 文件混桶：已迁 slice 读新桶、未迁读旧桶，**全部可读**（自描述） | 重跑 `tier set`（第 1 步 CAS 对相同目标直接通过），按"位≠目标"续迁；或等 compact 收敛 |
| F-3 | 迁移：ref-1 归零后、delslices 执行前崩溃 | 旧对象待删 | 现状 delslices 机制重启后继续（自路由删除） |
| F-4 | 写入：PUT 成功、meta Write 未提交崩溃 | 孤儿对象 | 现状语义，gc 清理（窗口保护内不误删） |
| F-5 | writeback：meta 已提交、staged 未上传崩溃 | slice 存在、对象不在（INV-2 暂缺口） | 重启 `scanStaging` 回放（key 自路由）；盘损则数据丢失——**writeback 的既有风险，多桶不放大** |
| F-6 | `config` 加桶/改 tier 中途（Format 写入是单事务） | Format 要么旧要么新 | 无中间态；传播延迟场景见 W-4 |
| F-7 | SetAttr 已翻、迁移完全没跑 | 纯"意图未收敛" | `tier status` 可见；新写已走新桶；重跑或等重扫（compact 只对碎片化 chunk 兜底，见 §5.6） |
| F-8 | 新对象在窗口被击穿后遭 gc 误删、事务已提交 | chunk 指向缺失对象 | 提交后 Head 抽验发现 → 旧副本仍在迁移保留队列（INV-6，不随 TrashDays=0 消失）→ 重拷自愈；fsck 亦可检出并走同一修复 |
| F-9 | 桶 draining/sealed 阶段崩溃 | 状态机持久于 Format，无中间态 | 重启后按状态继续排空；sealed 拒新写由全部客户端依据 Format 共同强制 |

**恢复设计的总原则**：所有中断态都落在"自描述、可读、可幂等重跑"的安全域内；
唯一需要主动补救的只有孤儿对象（gc 兜底）。不存在需要人工判断"数据到底在哪"
的状态。

### 5.10 文件类型语义

桶路由信息只存在两处——`Attr.Tier`（意图）与 slice id 高位（现实），故一个
inode 类型是否受多桶影响，取决于它有没有 slice：

| 类型 | 数据面 | 语义 |
|---|---|---|
| 普通文件 | 有 slice | 主场景，§5.1–5.9 全覆盖 |
| 目录 | 无 | `Attr.Tier` 仅作**继承源**（`doMknod` 创建子节点时继承，三引擎一致）；`tier set <dir>` 默认只改意图（影响此后新建），`-r` 递归对子文件逐个迁移，目录自身无数据可迁 |
| 软链接 | 无（target 只存元数据：Redis `s$inode` / SQL `symlink` 表 / TKV 同构） | 无路由问题；创建经 `Symlink→doMknod` 同样继承 Tier 但为**惰性字段**。迁移语义见 §5.4（meta 层无法忠实跟随，`tier set` 遇软链接明确报告无数据；递归与规则永不跟随） |
| 硬链接 | 共享同一 inode | **天然一致**：所有链接路径共享同一 `Attr.Tier` 与同一组 slice，不存在"两路径两 tier"的表达空间（同 chmod 的 inode 属性语义；nlink>1 时迁移影响全部链接，用户文档提示）。与 clone 的区别：clone=新 inode 共享 slice（存在 M-4 场景），硬链接=同 inode（连 M-4 都不存在）。并发：不同路径同时迁移落到同一 inode 的 Attr CAS，复用 M-1 串行化；递归扫描遇多 dentry 第二次幂等跳过 |
| FIFO/设备/socket | 无 | Tier 惰性继承，无影响 |
| Trash 文件 | 保留 inode+slices | 过期删除走 sliceRef 归零 → 自路由（同 F-3） |
| 内部虚拟文件（`.stats` 等） | 无 | 无影响 |

## 6. 多客户端并发矩阵（汇总）

| 操作 A \ 操作 B | 写入 | 读取 | 迁移 | compact | clone | gc | config 改定义 |
|---|---|---|---|---|---|---|---|
| **写入** | POSIX 现状（W-1） | 现状 | W-2/M-2：旧位正确，重扫收敛 | 现状事务重试 | 现状 | G-2 窗口 | W-3/W-4：快照隔离或 EIO |
| **读取** | — | 无冲突 | R-1：延迟删除窗口 + 失效重读 | 同 R-1（现状语义） | 无冲突 | 无冲突 | R-3：原子交换 |
| **迁移** | — | — | M-1：Attr CAS 互斥 | M-3：乐观冲突重试 | M-4：ref 计数表达共享 | M-5：reservation+窗口 | op-C 仅改 Sc，无数据操作 |
| **compact** | — | — | — | 现状互斥 | 现状 | 现状窗口 | 快照隔离 |
| **clone** | — | — | — | — | 现状 | 现状 | 无关 |
| **gc** | — | — | — | — | — | G-3 幂等 | G-4 retire 协议 |

结论：**全表无新增"需要跨客户端协调"的格子**。所有互斥都落在单点原语上
（引擎事务、Attr CAS、mtime 窗口、ref 计数），没有分布式锁、没有条件写
（ForbidOverwrite）依赖。

## 7. 兼容性

### 7.1 版本门控（两阶段激活）

- 单桶卷（无 Buckets 实体项、所有 Tier 的 BucketRef=0）：行为与现状**完全
  一致**，不抬版本；
- **已证伪的初版假设**（第二轮评审 S0-3）：`CheckVersion` 只在挂载时
  `Load(true)` 执行，已挂载老客户端心跳走 `Load(false)` **不复查版本**
  （base.go:914-925），并会静默丢弃不认识的 Buckets 字段继续运行——
  "抬版本自动挡住所有老客户端"不成立，老二进制无法 retrofit；
- **两阶段激活协议**：
  1. Phase A：`config` 抬升 `MinClientVersion` → 此后新挂载被 `Load(true)`
     拒绝；随后扫描**活跃会话的客户端版本清单**（session 记录含版本），
     存在低版本会话 → 拒绝进入 Phase B 并列出待处理会话，由运维升级/驱逐；
  2. Phase B：低版本会话清零后，才允许 `config` 创建 Buckets 实体项与
     非 0 BucketRef 的 Tier——此后系统内不可能存在读不懂多桶数据的客户端。
- 语义不兼容（老客户端读多桶数据必 404）只能挡在门外，不能兼容。

### 7.2 dump/load

- 打标 id 以 opaque uint64 透传二进制 dump（chunk 原始 24 字节）与 JSON dump，
  格式零改动；
- load 新增两项校验（§3.1）：计数器域、BucketRef 存在性；
- `Buckets`/`Tiers` 随 Format 整体 dump；脱敏遵守 §3.2。

### 7.3 回滚（软单向门）

id 即 key ⇒ 清位 = 换 key = 搬对象。退回单桶 = 把所有非 ref0 数据迁回
（op-A 全量）。启用第二个桶前必须知情确认。中间降级态（ADR-1.1 半可变下
BucketRef 不可改，降级走 attr 而非改定义）：对目标目录/文件批量
`tier set` 到指向 ref0 的 tier（仅 SetAttr 意图变更，不迁数据）——新写全回
默认桶，旧数据保读，随重扫迁移回流。

**备份有效性坍缩警示**（第二轮评审新增）：meta 备份的可恢复性依赖其引用的
对象仍然存在。大规模迁移持续删除旧对象 ⇒ 迁移完成后，**早于迁移的全部
meta 备份的有效性坍缩到保留期（INV-6 / TrashDays）之内**。运维军规：大规模
迁移完成后立即产出新的 meta 备份；恢复演练必须包含对象层引用完整性校验
（fsck）。DR 细化见 §12.5。

## 8. 安全

**凭证分发模型（决策 #6，已确认）——凭证本地化为主推模式**：

- **Format 只存桶身份**（Storage/Endpoint/State，路由正确性所需的集中信息），
  Bucket 项凭证字段留空 ⇒ 客户端启动时为每个注册桶用**本地凭证链**初始化
  client：按 ref 命名的环境变量（`JFS_BUCKET<ref>_ACCESS_KEY/SECRET_KEY`）、
  凭证文件、云厂商 instance role/IRSA。现状先例：单桶已支持 format 不存
  AK/SK、mount 走 env/instance profile，多桶只是扩展为按 ref 的命名约定；
- **结构性收益**：meta 与 dump 中不存在凭证 ⇒ "自解密信封"风险整体消失；
  每客户端最小权限成为可能（只读客户端配只读凭证，gc/迁移 worker 独立身份
  持删除与列举权限）；
- **代价（部署方知情）**：每台客户端为其可访问的桶配置本地凭证（K8s Secret
  注入 / env / 文件）；缺某桶凭证的客户端读该桶文件得 auth 错误——符合
  "宁可失败"原则，也是合法的裁剪部署（只碰热数据的客户端可不配冷桶凭证）；
- **信封便利模式（保留）**：凭证写入 Format（信封加密）适合小规模部署。
  诚实评估：`Format.Encrypt` 密钥派生自卷 UUID 且与密文同存（config.go:237），
  **防护等级 = 防误看，不防任何能读 Format 的攻击者**；多桶信封 = N 朵云
  凭证同一信封，任一客户端沦陷即全部泄露。生产跨账号部署应使用本地化模式。

其余条款：

- 信封模式下 Buckets 凭证纳入 `Format.Encrypt/Decrypt` 与 dump `keepSecret`
  脱敏（§3.2）；
- 凭证轮换：本地化模式 = 客户端本地操作 + 进程内 reload；信封模式 = 注册表
  可变域操作，reload 原子交换实例（§4）；
- 跨账号最小权限：每桶凭证只授予该桶读写删；gc/fsck 需列举权限，文档注明。

## 9. 评审必须项（两轮合并，Must-fix）

第一轮（设计者自审 + 红队）与第二轮（独立外部评审）合并去重后的完整清单。
**S0 全部闭环前不得进入 Phase 1 实现；位布局在 §14 决策确认前不得冻结。**

**S0（丢数据 / 根基级）**

| # | 条款 | 落点 | 来源 |
|---|---|---|---|
| S0-1 | 错位对象删除纪律：INV-7 副本安全不变量为总纲（单副本必在目标端、双副本至少一个在目标端、删除仅随正证据）→ gc 内置 heal 协议（copy-verify-delete，§5.7）；PUT 点自断言 + 身份标记复核两道预防线（§4）；注册三层探测（§3.2）；**注册后的桶间手动拷贝列为运维禁令**（用户确认） | §3.2 / §3.4 INV-7 / §4 / §5.7 | 红队发现；INV-7 与 heal 闭环采纳自决策讨论 |
| S0-2 | migration reservation（首道防线）+ gc 窗口安全下限（封 `JFS_GC_SKIPPEDTIME` 后门）+ INV-6 独立保留期（脱钩 TrashDays=0 立即删）+ 提交后 Head 自愈 | §3.4 / §5.4 / §5.7 | 双方 |
| S0-3 | 版本门控两阶段激活（活跃会话版本扫描）；撤回"机制已存在"（`Load(false)` 不复查已证伪） | §7.1 / M-7 | 双方（外部证伪） |
| S0-4 | key namespace 路由表（`meta/`、`testing/`、`juicefs_uuid` 控制对象恒 ref 0）+ chunk key 解析失败显式报错、绝不回退 ref 0 | §4 | 外部独有 |
| S0-5 | 迁移单元 = 完整 block manifest：全部 block 复制 + 逐块校验后才允许 CAS 换 ID | §5.4 | 外部独有 |

**High**

| # | 条款 | 落点 |
|---|---|---|
| H-1 | `PlacementKey{BucketRef, Sc}` 替代 TierKey 类型重载（现状未知值静默回退 tiers[0]）；staging footer schema 扩展 + 旧 footer 兼容规则 | §5.1 / §5.2 |
| H-2 | 桶生命周期状态机 `active→draining→sealed→retired(→tombstone)`；"最终策略 vs 严格排空"语义二分，严格排空需 generation fence | §3.2 / M-2 |
| H-3 | `ReplaceSliceEntries` 按条目位置语义 + 各引擎原生 ref 计数约定（Redis 存储值=refs-1）+ 同 id 多条目（CopyFileRange）测试向量 | §5.4 |
| H-4 | 三引擎 slice 重写事务统一语义（乐观冲突整批重试、幂等断点）+ 共享测试 | §5.4 |
| H-5 | gc/fsck/destroy 放弃全局 k 路归并 → 逐桶独立扫描/checkpoint/报告；List 错误上抛（现状无限重试） | §4 / §5.7 |
| H-6 | 持久迁移 Job 控制面（job id / lease / checkpoint / 限速 / 进度 / 失败清单）前移至 Phase 2 | §10 |
| H-7 | 入口适配验收清单（mount/gateway/webdav/sync-jfs/Java SDK/gc/fsck/destroy/config/`vfs.CalcObjects`）+ ObjectStorage 全接口多桶语义 + key 派生四处复制收敛 | §4 / §10 |
| H-8 | 成本模型与滞回：同云 server-side copy 快路径、auto 规则冷却期/预算上限、迁移缓存失效预警 | §12 |

**Medium**

位段避 bit63 + 位域测试向量表（§3.1）；PG uint64 边界回归；凭证加密+脱敏
覆盖（§3.2/§8）；ref 0 唯一权威来源（§3.2）；Reload 拆分 + atomic.Pointer
（含现存竞态前置修复，§4）；`--storage-class` 挂载参数废弃告警、config
tier×bucket 互斥解除、Shards 互斥；回滚知情确认 + 备份军规（§7.3）；
per-bucket/tier 可观测指标与 `tier status` 收敛度量（§12.4）；rename 语义
决策（§11.7）；panic → 显式错误（§3.1）；JSON dump id 超 2^53 的外部工具
精度告警（§7.2 注记）。

## 10. 分期实施

**Phase 0（前置门槛）**：§9 全部 S0 条款的设计细化 + §14 决策确认 →
位布局冻结评审。

**Phase 1 数据格式与路由**（完成后：目录继承写入不同桶即可用）

1. key 派生收敛为单一函数（4 处复制点）+ 位域测试向量表；
2. 位布局 + 打标（`prepareID`）+ 三处守恒校验（显式错误）；
3. Format Buckets/Tiers schema（含状态机字段、ref 0 虚拟合成）+ 加密/脱敏
   + config 命令（加桶、改 tier 定义、两阶段激活的会话版本扫描）；
4. bucketRouter：key namespace 路由表 + `PlacementKey` + ObjectStorage 全
   接口语义 + 逐桶独立扫描 + Reload 拆分（含 atomic.Pointer 前置修复）；
5. 读/写/staging（新 footer schema）/compact/delete 路由贯通；
6. gc（MISPLACED/UNKNOWN_REF 只报告、reservation 感知、窗口下限）/ fsck /
   destroy / info 多桶适配；
7. 版本门控两阶段激活 + Shards 互斥 + `--storage-class` 废弃告警；
8. 凭证本地化模式：按 ref 的本地凭证链解析（env/文件/instance role，
   决策 #6）；信封模式的加密/脱敏并存；
9. 测试：三引擎共享测试、dump/load round-trip（含计数器域与 ref 存在性校验）、
   PG 边界、混合版本（含已挂载老客户端行为）、加密 round-trip、
   gc 泄露/错桶/过期 Format 注入。

**里程碑顺序**：mount + 核心工具（gc/fsck/destroy/config/info）先行验收；
**SDK（Java）与 gateway 为 Phase 1 内后置里程碑**——发布前必须完成适配与
测试，但不阻塞主线开发（决策 #3）。

**Phase 2 迁移**

1. op-A 原语：Attr CAS + reservation + block manifest 复制校验 + 按条目
   替换与引擎原生 ref 约定 + 会话去重映射 + 迁移保留队列（INV-6）+
   提交后 Head 自愈；
2. **持久 Job 控制面**（H-6）：job id / lease / inode+chunk checkpoint /
   限速与并发预算 / 进度与失败清单——TB 级跨云迁移的断点与多实例协作
   不能依赖进程内重扫；
3. `tier set`（op-A/op-B 自动选路，同云同账号走 server-side copy 快路径）
   + `tier status`（意图 vs 现实收敛度量）；
4. 冷冻层级前置（Head 检测 → restore → 重试）；
5. 桶状态机 draining/sealed 执行面（新 open 拒绝、sealed 拒写）；
6. 测试：迁移 × 写 × compact × clone × gc 交叉、中断注入（F-1~F-9）、
   同 id 多条目向量、reservation 过期路径。

**Phase 3 策略自动化**

1. tier 定义 CRUD 完整化（op-C 改 Sc）+ retire/tombstone 全流程工具；
2. `tier apply` 规则引擎：**一次性命令 + 外部 cron 调度**（决策 #2，断点
   状态在 meta Job 表，每次运行拾取 checkpoint 续跑）；**滞回与冷却期、
   每日迁移预算上限**（§12.3）、分片；
3. per-bucket 用量统计（决策 #8：扫描型，不做写路径实时计数器）；
4. 凭证分发增强（KMS 引用等，视部署反馈）；`WriteClass` 字段视需求实现
   （决策 #5：schema 预留）。

## 11. 开放问题（决策进展）

**已确认**：

1. ~~BucketRef 位宽~~ →（ADR-1.2）4 位，终身 16 名额；
2. ~~`tier apply` 宿主~~ → **一次性命令 + 外部 cron 调度**：断点/进度/限速
   状态持久于 meta 的 Job 表（ADR-1.4），cron 拉起的每次运行拾取 checkpoint
   续跑——宿主无状态，与持久 Job 控制面兼容；
3. ~~SDK/gateway Phase 1 范围~~ → **mount + 核心工具先行验收；SDK/gateway
   为 Phase 1 内后置里程碑**（发布前必须完成，不阻塞主线开发）；
5. ~~归档直写~~ → **tier schema 预留 `WriteClass` 字段、暂不实现**；归档层
   直写成本先靠文档 + 桶侧生命周期；
6. ~~凭证分发~~ → **凭证本地化为主推模式**（凭证不入 meta，本地凭证链按
   ref 解析；信封模式保留为便利选项），详见 §8；
7. ~~rename 语义~~ → **维持不重继承**（POSIX inode 属性语义，同 chmod）；
   "目录即层级"的需求由 `tier apply` 规则 + 滞回（§12.3）兜底，用户文档
   明确此行为；
8. ~~per-bucket 用量统计~~ → **Phase 3**（届时优先扫描型统计，不做写路径
   实时计数器）；
9. ~~严格排空~~ →（ADR-1.3）不 fence，最终收敛；严格排空为桶退役 sealed
   阶段能力。

**未决（Phase 2 设计细化时定）**：

4. retire 的 N 值、sealed 排空验证手段与 tombstone 清单格式（建议默认：
   N=3 可配 + session 枚举验证 + JSON 残留清单，届时确认）。

## 12. 成本模型与故障域（第二轮评审新增）

### 12.1 op-A 成本量化

10TB 文件 = 2.6M 个 4MB block 对象。跨云迁移一次性成本：egress ≈ **$900+**
（按 $0.09/GB）+ 2.6M GET + 2.6M PUT 请求费 + meta 数万批事务；源为归档层
另加解冻费与小时级等待。**同云同账号必须走 server-side copy 快路径**：对象层
新增可选 `CopyFrom(srcRef, key)` 接口（S3 CopyObject 类语义），免 egress、
免数据过客户端——这是 op-A 在同云场景从"贵"降到"请求费"的关键优化（H-8）。

### 12.2 迁移的缓存失效成本

op-A 换 id ⇒ 该文件在**全部客户端**的本地磁盘缓存整体作废，读流量转移到
更冷（可能需解冻）的目标桶——大规模迁移需配套 warmup 或迁移限速窗口。
op-B（同 key Copy）缓存保活。这是两种操作被低估的隐藏成本差，`tier set`
文档必须向用户呈现。

### 12.3 自动规则滞回（防乒乓账单）

atime 抖动数据集上"判冷→迁走→被读→判热→迁回"的每一跳都是真实账单。
`tier apply` 必须内置：**冷却期**（同文件两次 op-A 最小间隔）、**不对称
滞回阈值**（如降冷 atime>90d / 回热 atime<7d）、**预算上限**（每日迁移
字节数/请求数/费用上限，超限暂停并告警）。无滞回的规则引擎不允许发布。

### 12.4 故障域与可观测性

单桶：桶挂 = 全挂，诊断平凡。多桶：任一桶挂 = **部分文件/部分 chunk 不可
读，表象与真丢块相同**。要求：

- per-bucket 健康探测与独立指标（请求率/错误率/延迟/字节，沿用
  storage_class label 先例扩展 bucket label）；
- fsck/读路径区分"桶不可达"（EIO + 桶标识）与 BROKEN（对象确实缺失）；
- 降级语义：单桶不可达只影响引用它的文件，不得演变为全卷故障；
- `tier status` 输出：per tier 的 desired vs actual 字节与 slice 数、
  未收敛清单、迁移 Job 进度/失败分类、staging 最大滞留时长、
  reservation 存量与年龄、retire blocker 列表。

### 12.5 备份 / DR

多桶无全局时间点快照：恢复 = meta(T) + **每个桶**在 T 之后未删除 meta(T)
所引用的对象。迁移持续删除旧对象 ⇒ 历史 meta 备份有效性坍缩到保留期内
（§7.3 军规：大迁移后立即重做 meta 备份）。Phase 2 交付物需包含：跨云
恢复时序文档、逐桶恢复清单工具、恢复后 fsck 引用完整性校验流程。

## 13. 备选方案对比（Alternatives）

设计演化中比较过的方案（详细推演见评审对话记录）：

| 方案 | 核心 | 结论 |
|---|---|---|
| A. 文件级 Attr 路由 | bucket+sc 合并存 Attr，读靠 attr 贯通 + 404 兜底 | 否决：clone/删除/GC 正确性靠修补件拼装；writeback footer 过期有丢数据路径 |
| B. sliceID 高位记 桶+类 | tier=bucket+sc 编码进 id 高 2 位 | 否决：改 sc 也要全量重写 slice；2 位=4 组合封死 |
| C. sliceID 记桶、Attr 记类 | 维度分离，无 tier 抽象 | D 的子集：正确性同 D，但用户直面两维、无策略层 |
| **D. 本方案** | C + 一维 tier 策略层 + 桶注册表 | 采纳（附 §9 条款） |
| E. 稀疏 id→bucket 映射表 | 只记迁移过的 slice（默认桶免记录），id/key 不变 | **未充分评估**（第二轮评审指出），见下 |

**方案 E 的诚实对比**：迁移不换 key ⇒ **本地缓存保活**（消解 §12.2）、
**无 key 固化**（endpoint/桶数彻底自由，消解 16 预算与 S0-1 别名问题）、
无位宽契约。代价：读路径引入一次映射查询（可客户端缓存，miss→404→回查
兜底）；删除/gc 需 join 映射表；**同 key 跨桶复制重新引入双向迁移互删竞态**
（正是本方案用"新 rawID"消灭的那一类），需 (id,bucket) 元组删除队列 +
事务化驻留记录另行闭环，复杂度与 reservation 相当。落选理由：读路径引入
元数据依赖，破坏"数据面自治"这一根设计原则。**重评触发条件**：若 §11.1
的 16 名额预算被产品否决，E 是首选替代路线。

## 14. 决策变更记录（ADR-1，已确认）

**变更**：从原《分层存储设计》多桶模型——对外 **4 个不可变 Tier**
（Tier = Bucket + StorageClass 绑定）、TierID 不复用、sliceID 高 2 位、
持久 Job + 独立 Worker、inode 迁移 fence——演化为本方案。

**变更动机**：① 分离"便宜的改 sc"（SetAttr+同 key Copy）与"昂贵的搬桶"
（slice 重写）的成本曲线——原模型改任何 tier 属性都是最贵路径；② tier
可管理性（原模型改 tier 需"预留空层级中转"）；③ 新 rawID 消除
ForbidOverwrite 对象层依赖，把双向迁移竞态从"条件写堵漏"变为结构性消失。

**四项决策（已逐项确认）**：

| # | 决策点 | 结论 |
|---|---|---|
| 1 | 对外 tier 模型 | **半可变策略指针**：`Sc` 可改（成本操作、不影响正确性）；`BucketRef` 创建后**不可改**，换桶 = 新建 tier + 显式迁移。理由：消除全可变的三项代价——误操作爆炸半径（改指针 = 百万文件瞬间 unconverged + 自动搬数据账单）、审计不可追溯（Format 无定义变更历史）、多客户端传播窗口混桶；同时保留相对不可变模型的核心优势（改 sc 便宜、tier 数量 256、endpoint 变更已由注册表可变域承接）。已传播至 §2.1/§3.2/§5.4 op-C/W-3/§7.3 |
| 2 | sliceID 位宽 | **4 位，终身 16 个注册名额**（明确"名额是消耗品"框架后确认）。位布局冻结 |
| 3 | 迁移写语义 | **不 fence，最终收敛**：如实显示 unconverged；严格排空（generation fence）后置为桶退役 sealed 阶段的能力（H-2） |
| 4 | 持久迁移 Job | **Phase 2 必需**（job id / lease / checkpoint / 限速 / 进度） |

**位布局自本记录确认之日起冻结**；剩余进入实现的前置 = §9 S0 条款的
实现级闭环 + §11 未决项中标注 Phase 1 相关者（#3、#6、#7）。
