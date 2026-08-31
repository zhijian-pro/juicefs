# 多桶分层存储设计：sliceID 记桶引用 + Attr 记 tier 策略

> 状态：设计评审通过（Request changes 条款已并入本文 §9）
> 分支：`multi-bucket-design`
> 前置阅读：现有单桶分层实现（`Attr.Tier` + `Format.Tiers` + `TierKey` ctx 链路）

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
             Format.Tiers[tierID] = {BucketRef, Sc}      ← 可变的策略指针
                 │
                 ▼
数据路由层:  sliceID 高位 = BucketRef ──▶ Format.Buckets[ref] = {Storage, Endpoint,
                                            AK/SK(加密), State}   ← 位置标识不可变、只增不删
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
    bucketRefMask  = uint64(0xF) << bucketRefShift
    rawIDMax       = uint64(1) << bucketRefShift
)

func stampID(rawID uint64, ref uint8) uint64 {
    assert(rawID < rawIDMax)         // NewSlice 断言，越界直接 panic
    assert(ref < 16)
    return rawID | uint64(ref)<<bucketRefShift
}
func bucketRefOf(id uint64) uint8 { return uint8((id & bucketRefMask) >> bucketRefShift) }
func rawIDOf(id uint64) uint64    { return id &^ (bucketRefMask | 0xE0<<56) }
```

守恒校验（三处）：

1. `NewSlice`：分配出的 rawID 越界 → 拒绝并报警（理论不可达）；
2. `format` / `load`：`nextChunk` 计数器必须 < `rawIDMax`，否则显式拒绝；
3. dump 载入：出现的 BucketRef 必须存在于目标卷注册表，否则显式拒绝
   （不静默丢失，AGENTS.md 红线）。

### 3.2 Format 扩展

```go
type Bucket struct {
    Ref       uint8  // 注册表下标，永不复用
    Storage   string // "s3"/"oss"/"gs"...   ┐
    Endpoint  string // bucket URL           ┤ 位置标识：不可变
    AccessKey string //                      ┐
    SecretKey string // 落库前必须加密        ┤ 凭证/参数：可变（支持轮换）
    State     string // active | retired     ← 删除只允许 retire，ref 永不复用
}

type Format struct {
    // ...现有字段...
    Buckets map[uint8]Bucket // ref 0 = 默认桶（等价现有 Storage/Bucket/AK/SK 字段）
    Tiers   map[uint8]Tier   // 现有结构扩展
}

type Tier struct {
    ID        uint8
    Sc        string // storage class（现有字段）
    BucketRef uint8  // 新增：指向 Buckets；0 = 默认桶
}
```

- `Format.Encrypt/Decrypt` **必须**扩展遍历 `Buckets[].AccessKey/SecretKey`
  （现状只处理三个固定字段）；三引擎 dump 的 `keepSecret` 脱敏同步扩展。
- ref 0 的 Bucket 项由现有 `Storage/Bucket/AccessKey/SecretKey` 字段合成，
  保证单桶卷的 Format 不发生任何变化（老卷零感知）。

### 3.3 Attr.Tier 语义

编码不变（Attr 尾部可选字节 + SQL `tier_id` 列），语义从"存储类"升级为
"策略层级指针"。继承逻辑不变（mknod 继承父目录）。

**意图 vs 现实**：`Attr.Tier` 表达"该文件的数据应该在哪"（意图）；slice 的
桶位表达"实际在哪"（现实）。二者允许暂时不一致（迁移中 / 中断后），
读以 slice 为准、写以 Attr 为准，`tier status` / fsck 负责度量与收敛。

### 3.4 不变量

- **INV-1（驻留）**：id 位声明 ref=N 的对象，只允许存在于桶 N；
  出现在其他桶 = 泄露，可删。
- **INV-2（可读）**：meta 中存在的 slice，其 id 位声明的桶中必须有对应
  block（延迟删除窗口内例外，同现状 compact 语义）。
- **INV-3（注册表）**：Buckets 的位置标识（Storage/Endpoint）一经创建不可变；
  ref 永不复用；retire 前必须经全量扫描证明零引用。
- **INV-4（ID 域）**：rawID < 2^56；bit 60-63 恒 0。
- **INV-5（GC 窗口）**：任何"对象已 PUT、meta 未提交"状态的持续时间必须
  远小于 gc 的 mtime 保护窗口（现状 1h）。

## 4. 存储层

```go
// 替换现有 initStorageTiers 装饰器，构建于 Buckets 之上（与 Tiers 解耦）
type bucketRouter struct {
    stores [16]ObjectStorage // 按 ref 索引；每项 = prefix(name+"/") 包装的实例
}

func (r *bucketRouter) route(key string) ObjectStorage {
    return r.stores[bucketRefOf(parseSliceID(key))]
}
// Get/Put/Head/Delete/Restore: route(key).Xxx(...)
// Put/Copy 额外从 ctx TierKey 取 sc（现状机制不变）
// ListAll: 对所有 active/retired 桶做堆式 k 路归并（同 sharding.go 实现）
```

装饰器顺序：`encrypted( bucketRouter{ ref→prefix(blob) } )`。
卷级 `Compression`/`EncryptKey` 全局统一，跨桶数据格式一致。

**Reload 拆分**（现状对任何 Tiers 变化整体重建 storage）：

- Buckets 新增 / 凭证变更 → 只重建对应 ref 的 storage 实例（`atomic.Pointer` 交换）；
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
        ctx := WithValue(ctx, TierKey{}, s.h.sc) // sc 走瞬时载体
        router.Put(ctx, key(s.id, indx, len), block) // 桶由 key 中 id 位决定
    }
    meta.Write(inode, chunkIdx, slice{id: s.id, ...}) // meta 提交（含 sliceRef+1）
}
```

**多客户端并发分析（写）**

| 编号 | 场景 | 行为与结论 |
|---|---|---|
| W-1 | C1、C2 并发写同一文件（各自 open 快照的 tier 不同，例如中间隔了 tier set） | 各自的 slice 打各自的桶位，**都自描述、都可读**。文件暂时混桶，由迁移/compact 收敛。POSIX 对并发写本就不保证内容顺序，此处不引入新语义。 |
| W-2 | 写入 与 `tier set`（SetAttr 翻转）并发 | 已 open 句柄继续写旧桶（快照），落下的是"旧位但正确"的数据；迁移工具重扫收敛（见 5.4）。**不存在错位数据**（对比文件级方案：attr 已新、数据在旧桶且无从判定）。 |
| W-3 | 写入 与 tier 定义变更（管理员改 `Tiers[t].BucketRef`）并发 | 句柄快照的是解析后的 bucketRef，且注册表项不可变 ⇒ 在写句柄不受影响。新 open 才使用新定义。 |
| W-4 | C1 刚 `config` 加桶并设 tier，C2 的 Format 缓存尚未刷新（OnReload 周期），C2 打开 attr.Tier=新 tier 的文件 | C2 解析失败 → 强制 reload Format 重试 → 仍失败则 **EIO**。规则：宁可失败，绝不静默落错桶。 |
| W-5 | ID 批分配竞争 | 各客户端独立获取 4096 大小的 rawID 批（现状 `incrCounter("nextChunk")`），打标是本地位或，无新增竞争点。 |

### 5.2 writeback / staging

```go
func (s *wSlice) upload(indx) {
    key := key(s.id, indx, blen)          // 打标 id 已在 key 中 → 桶信息已持久化在文件名里
    if writeback {
        bcache.stage(key, data, footer{sc: s.h.sc}) // footer 只需存 sc 快照
        // 上传（立即或延迟）：
        //   桶：key 中 id 位自路由（重启回放 scanStaging 同样成立）
        //   sc：读 footer（写入时刻的意图快照，不受 tier 定义后续变更影响）
    }
}
```

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
op-A 搬桶（bucketRef 变化）   : 数据拷贝 + slice 重写        —— 最贵
op-B 改 sc（同桶）            : SetAttr + 同 key Copy        —— 便宜（现状 tier set 路径）
op-C 改 tier 定义             : 纯 Format 变更，零数据操作    —— 免费（新数据走新定义，旧数据可选 op-A 收敛）
```

**op-A 伪代码（核心）**：

```go
func migrateFile(inode, dstTier) error {
    // 1. 意图先行：CAS 翻转 Attr（新写入立刻走新桶；并发迁移互斥的锚点）
    if !meta.SetAttrCAS(inode, expectTier=curTier, newTier=dstTier) {
        return ErrConflict // 另一个迁移已改意图，本工具退出
    }
    dst := format.Tiers[dstTier]

    for each chunk of inode {
        slices := meta.ReadChunk(inode, chunkIdx)
        for batch := range batches(slices, 64) {      // 小批：约束 INV-5（GC 窗口）
            for s := range batch {
                if bucketRefOf(s.id) == dst.BucketRef { continue } // 幂等：已在目标桶
                newID := stampID(meta.NewSlice(), dst.BucketRef)   // 全新身份，永不碰撞
                data, err := router.Get(key(s.id, ...))            // 逐对象
                if err == ENOENT { skip }                          // S-1：staged 未上传，下轮再迁
                router.Put(ctx{sc: dst.Sc}, key(newID, ...), data) // 无需 ForbidOverwrite：新 key 全局唯一
                rewrites = append(rewrites, {old: s.id, new: newID})
            }
            // 2. 每批立即提交（PUT→提交窗口 << 1h，满足 INV-5）
            err := meta.Txn(func(tx) {
                if tx.GetAttr(inode).Tier != dstTier { // 防乒乓：意图已被并发迁移改写
                    return ErrSuperseded               // 整个迁移终止，让位给新意图
                }
                cur := tx.ReadChunk(inode, chunkIdx)
                if !containsAll(cur, rewrites.old) {   // 乐观并发：chunk 被并发写/compact 改过
                    return ErrRetry                    // 整批重读重试（新对象成孤儿，交给 gc）
                }
                tx.ReplaceSliceIDs(chunkIdx, rewrites) // 24 字节等长原位替换
                for r := range rewrites {
                    tx.SliceRef(r.new, +1)
                    tx.SliceRef(r.old, -1)             // 归零 → 进 delslices 延迟删除（自路由）
                }
            })
        }
    }
    // 3. 收敛检查：迁移期间的并发新写（W-2）可能又落了旧桶
    if !converged(inode, dst.BucketRef) { rescan(inode) } // 重扫直到收敛或达到重试上限
    return nil
}
```

**无锁对象层的删除安全原则**：对象存储没有锁与事务，因此本设计规定**对象层
永远不承载决策**——迁移工具没有"删除"步骤，删除只能是 meta 事务内 ref 归零
的延迟副作用。由此，"刚写入的对象被并发迁移删除"需要同时突破三道防线：
① 新对象 key 含全新 rawID（计数器原子分配、永不复用），无人知晓、无从同名
互删；② 解引用它的事务必须先"看见"它并已把数据以更新的身份复制走
（copy-then-swap 顺序）；③ 唯一不受事务保护的窗口（PUT 后、meta 提交前的
孤儿态）由 gc 的 mtime 窗口（1h）+ 小批提交（INV-5）保护——该假设与现有
正常写入路径完全同构。

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
| M-2 | 迁移 与 并发写同文件 | 写走 Attr 新值（open 晚于 CAS）或旧快照（open 早于 CAS，落旧桶）。后者由第 3 步重扫收敛；重扫仍不净的（长期打开的写句柄）由 compact 最终收敛（compact 用当前 attr.Tier）。 |
| M-3 | 迁移 与 compact 同 chunk | 两者都在事务内做 chunk 原位替换 → 乐观冲突，一方 `ErrRetry`。compact 产物已带新桶位（attr 已翻转）→ 迁移重读后发现位正确，跳过。无死锁、无丢失。 |
| M-4 | 迁移 与 clone | clone 在事务内复制 slice 引用并 ref+1。若 clone 先行：迁移 ref-1 后旧 id ref 仍 >0 → **不删旧对象**，clone 文件继续可读（代价：两桶各一份，与原设计文档"clone 变两份数据，可接受"结论一致）。若迁移先行：clone 拿到的已是新 id。引擎事务保证两者串行化。 |
| M-5 | 迁移 与 GC | 批内"PUT 已成、meta 未提交"的新对象对 gc 是孤儿 → 依赖 mtime 窗口（1h）保护。**设计约束**：单批从首个 PUT 到提交必须 << 1h（batch=64 + 提交超时告警）；提交前发现批内对象 mtime 陈旧则重新 PUT 刷新。 |
| M-6 | 迁移工具自身多实例（如两台机器跑 `tier apply`） | 同 M-1，Attr CAS 天然互斥到文件粒度；目录级任务用分片（按 inode 取模）避免无谓冲突。 |
| M-7 | 迁移 与 老客户端 | 不可能并存：启用第二个桶时 `MinClientVersion` 已抬升，老客户端在 `Load` Format 时被 `CheckVersion` 拒绝（机制已存在）。 |

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
（事务重试）。**compact 是混桶文件的免费收敛器**：频繁改写的文件即使从未
显式迁移，数据也会随 compact 流向 Attr 当前指向的桶。

### 5.7 GC

```go
func gc() {
    maxMtime := now - 1h                          // 现状窗口（INV-5 的另一半）
    liveIDs := meta.ScanSlices()                  // 打标 id 全集（opaque 透传）
    for ref, blob := range router.buckets {       // 含 retired 桶
        for obj := range blob.ListAll("chunks/") {
            if obj.Mtime > maxMtime { skip }      // 保护未提交的写入/迁移
            id := parseSliceID(obj.Key)
            switch {
            case bucketRefOf(id) != ref:
                delete(obj)                       // INV-1：错桶残留（理论上仅 bug/手工产生）
            case !liveIDs.Contains(id):
                delete(obj)                       // 常规泄露：迁移/写入中断的孤儿、已删文件残留
            }
        }
    }
}
```

**并发分析（GC）**

| 编号 | 场景 | 行为与结论 |
|---|---|---|
| G-1 | gc 与 迁移并发 | 见 M-5：窗口 + 小批提交。窗口内的孤儿下轮 gc 清理。 |
| G-2 | gc 与 写入并发 | 现状既有语义（PUT→meta 提交秒级窗口 << 1h），多桶不改变假设。 |
| G-3 | 两个 gc 并发 | 删除幂等；`ListAll` 归并只读。与现状一致。 |
| G-4 | gc 与 桶 retire | retired 桶仍被扫描（清理残留），零引用证明由连续 N 轮 gc 零命中给出，之后才允许下线。 |

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
| F-7 | SetAttr 已翻、迁移完全没跑 | 纯"意图未收敛" | `tier status` 可见；新写已走新桶；重跑或等 compact |

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
| 软链接 | 无（target 只存元数据：Redis `s$inode` / SQL `symlink` 表 / TKV 同构） | 无路由问题；创建经 `Symlink→doMknod` 同样继承 Tier 但为**惰性字段**。CLI 语义：`tier set` 遇软链接**不跟随**（作用于链接 = no-op 并提示），递归遍历亦不跟随——防环、防止迁移越出目标子树 |
| 硬链接 | 共享同一 inode | **天然一致**：所有链接路径共享同一 `Attr.Tier` 与同一组 slice，不存在"两路径两 tier"的表达空间（同 chmod 的 inode 属性语义；nlink>1 时迁移影响全部链接，用户文档提示）。与 clone 的区别：clone=新 inode 共享 slice（存在 M-4 场景），硬链接=同 inode（连 M-4 都不存在）。并发：不同路径同时迁移落到同一 inode 的 Attr CAS，复用 M-1 串行化；递归扫描遇多 dentry 第二次幂等跳过 |
| FIFO/设备/socket | 无 | Tier 惰性继承，无影响 |
| Trash 文件 | 保留 inode+slices | 过期删除走 sliceRef 归零 → 自路由（同 F-3） |
| 内部虚拟文件（`.stats` 等） | 无 | 无影响 |

## 6. 多客户端并发矩阵（汇总）

| 操作 A \ 操作 B | 写入 | 读取 | 迁移 | compact | clone | gc | config 改定义 |
|---|---|---|---|---|---|---|---|
| **写入** | POSIX 现状（W-1） | 现状 | W-2/M-2：旧位正确，重扫收敛 | 现状事务重试 | 现状 | G-2 窗口 | W-3/W-4：快照隔离或 EIO |
| **读取** | — | 无冲突 | R-1：延迟删除窗口 + 失效重读 | 同 R-1（现状语义） | 无冲突 | 无冲突 | R-3：原子交换 |
| **迁移** | — | — | M-1：Attr CAS 互斥 | M-3：乐观冲突重试 | M-4：ref 计数表达共享 | M-5：小批 + 窗口 | op-C 免费，互不干扰 |
| **compact** | — | — | — | 现状互斥 | 现状 | 现状窗口 | 快照隔离 |
| **clone** | — | — | — | — | 现状 | 现状 | 无关 |
| **gc** | — | — | — | — | — | G-3 幂等 | G-4 retire 协议 |

结论：**全表无新增"需要跨客户端协调"的格子**。所有互斥都落在单点原语上
（引擎事务、Attr CAS、mtime 窗口、ref 计数），没有分布式锁、没有条件写
（ForbidOverwrite）依赖。

## 7. 兼容性

### 7.1 版本门控

- 单桶卷（Buckets 只有 ref 0、所有 Tier 的 BucketRef=0）：行为与现状**完全一致**，
  不抬版本；
- `config` 首次新增第二个 Bucket 时：强制 `MinClientVersion` 抬升（机制沿用
  `cmd/config.go` 现有 requireMinClientVersion 流程），老客户端在 `Load` 时被
  `CheckVersion` 拒绝——**语义不兼容（老客户端读多桶数据必 404）只能挡在门外，
  不能兼容**。

### 7.2 dump/load

- 打标 id 以 opaque uint64 透传二进制 dump（chunk 原始 24 字节）与 JSON dump，
  格式零改动；
- load 新增两项校验（§3.1）：计数器域、BucketRef 存在性；
- `Buckets`/`Tiers` 随 Format 整体 dump；脱敏遵守 §3.2。

### 7.3 回滚（软单向门）

id 即 key ⇒ 清位 = 换 key = 搬对象。退回单桶 = 把所有非 ref0 数据迁回
（op-A 全量）。启用第二个桶前必须知情确认。中间降级态：把所有 Tier 的
BucketRef 改回 0（op-C，免费）——新写全回默认桶，旧数据保读，随 compact
自然回流。

## 8. 安全

- Buckets 凭证纳入 `Format.Encrypt/Decrypt`（§3.2，Critical 条款）；
- dump `keepSecret=false` 时脱敏全部桶凭证；
- 凭证轮换 = 注册表可变域操作（INV-3），reload 原子交换实例；
- 跨账号最小权限：每桶凭证只需该桶的读写删权限；gc/fsck 需全桶列举权限，
  文档注明。

## 9. 评审必须项（并入设计的 Must-fix 条款）

| 级别 | 条款 | 落点 |
|---|---|---|
| Critical | 位段避开 bit63；三处 ID 域守恒校验；PG uint64 边界回归测试 | §3.1 |
| Critical | 桶凭证加密 + dump 脱敏全覆盖 | §3.2 / §8 |
| High | 迁移小批提交，PUT→提交窗口 << gc 1h 窗口；陈旧重 PUT | §5.4 M-5 / INV-5 |
| High | 三引擎 slice 重写事务统一语义（乐观冲突整批重试、幂等断点）+ 共享测试 | §5.4 |
| High | 入口适配验收清单：mount / gateway / webdav / sync(jfs://) / Java SDK / gc / fsck / destroy / config 连通测试 / `vfs.CalcObjects`；key 派生四处复制先收敛为单一函数 | §10 Phase 1 |
| High | 注册表可变域精确化：位置不可变、凭证可变、删除仅 retire | §3.2 / INV-3 |
| Medium | Reload 拆分（Buckets 重建实例 / Tiers 只换映射）+ atomic.Pointer | §4 |
| Medium | 挂载参数 `--storage-class` 覆盖 Tier0 的语义废弃（保留告警）；解除 config 的 tier×bucket 互斥拦截；Shards 与多桶 format 时互斥 | §10 Phase 1 |
| Medium | 回滚知情确认 + 降级态文档 | §7.3 |

## 10. 分期实施

**Phase 1 数据格式与路由**（完成后：目录继承写入不同桶即可用）

1. key 派生收敛为单一函数（4 处复制点）；
2. 位布局 + 打标（`prepareID`）+ 三处守恒校验；
3. Format Buckets/Tiers schema + 加密/脱敏 + config 命令（加桶、改 tier 定义）；
4. bucketRouter + ListAll 归并 + Reload 拆分；
5. 读/写/staging/compact/delete 路由贯通（多为零改动验证）；
6. gc / fsck / destroy / info 多桶适配；
7. 版本门控 + Shards 互斥 + 老参数处理；
8. 测试：三引擎共享测试、dump/load round-trip、PG 边界、混合版本拒载、
   加密 round-trip、gc/fsck 泄露注入。

**Phase 2 迁移**

1. op-A 原语（Attr CAS + 小批事务 + 幂等断点 + 收敛重扫）；
2. `tier set`（op-A/op-B 自动选路）+ `tier status`（收敛度量）；
3. 冷冻层级前置（Head 检测 → restore → 重试）；
4. 测试：迁移 × 写 × compact × clone × gc 交叉、中断注入（F-1~F-7）。

**Phase 3 策略自动化**

1. tier 定义 CRUD 完整化（op-C）+ retire 协议；
2. `tier apply` 后台规则引擎（path/size/atime → tier），限速、断点、分片。

## 11. 开放问题

1. BucketRef 位宽最终确认：4 位（16 桶）是否满足远期？扩位不可逆，需产品拍板；
2. `tier apply` 形态：一次性命令 vs 常驻任务 vs 独立组件；
3. Java/Python SDK 与 gateway 的 Phase 1 支持范围（全量 or 只读）；
4. retire 桶的"连续 N 轮 gc 零命中"中 N 的取值与操作流程；
5. 归档桶直写的成本策略：是否提供 `write-through-class`（先写 STANDARD，
   桶内生命周期转归档）作为 tier 定义可选项。
