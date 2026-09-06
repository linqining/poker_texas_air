# 死锁审查报告与修复记录

> 审查日期：2026-09-06。起因：线上出现过实锤死锁（commit 39a390e 修复）。
> 本文是对全工作区的系统性死锁审查结论 + 本次修复（8 项）的完整记录，
> 供后续 review 与回归对照。

## 1. 背景：39a390e 的实锤死锁

`texas/src/socket/handlers.rs` REBUY 回滚分支：持有 tokio `RwLock` **写锁**
`gs`（`SocketState.state`）期间调用 `broadcast::broadcast_to_table`，而后者
内部对**同一把锁**取读锁。tokio RwLock 不可重入 → 永久自锁，且该桌写锁
永不释放。修复方式：广播前显式 `drop(gs)`。

**核心教训**：`SocketState.state` 是覆盖**所有桌 + 所有玩家**的全局单锁，
tokio RwLock 不可重入、无超时；任何"持锁跨 await / 持锁调内部加锁的函数 /
持锁 spawn"都是死锁或全服冻结的种子。

## 2. 锁架构总览

### texas crate（tokio 异步侧，死锁重灾区）

| 锁 | 类型 | 位置 | 保护 |
|---|---|---|---|
| `SocketState.state` | tokio RwLock（全局单把） | socket/mod.rs:360 | 所有桌 `tables`、`players`、`disconnect_cancellers` |
| `SocketState.game_loop_registry` | tokio RwLock | socket/mod.rs:362 | 每桌 game loop 的 handle/sender/stop |
| `SocketState.processed_actions` | std RwLock（Arc） | socket/mod.rs:366 | C2 动作防重放缓存 |
| `Database.users` | tokio RwLock（Arc） | models.rs:32 | 用户/locked_chips 记账 |
| 每桌 `event_tx` | tokio mpsc(256)，`try_send` 非阻塞 | pokergame/table/mod.rs:427,524 | TableEvent → consumer 广播 |
| 每桌 action 通道 | tokio mpsc(100) | socket/mod.rs:479 | ActionRequest → game loop |
| 静态 std Mutex 若干 | BUCKETS/JOIN_BUFFER/PENDING_SETTLE/… | ratelimit/prove_log/hooks | 短临界区 |

**锁序**：全局一致为 `state → { processed_actions | db | 各 std Mutex }`，
`game_loop_registry` 从不与 `state` 嵌套——**无 AB-BA**。所有 std 锁均
`lock().ok()`/`into_inner()` 防中毒，无 `lock().unwrap()`。

### 根 crate 及其他成员（纯同步，无 tokio/async）

orchestrator.rs（4188 行）**零锁**：共享状态用 clone-and-replace 值语义，
`par_iter().map().collect()` 收齐后按序提交，无跨线程共享可变状态。
4 处静态缓存锁（TWIDDLE_CACHE/BINDING_CACHE/SETUP_CACHE/RECORDS）全部
"读→放锁→算→写锁 double-check"模式，重活在锁外，poison 安全。
并发面只剩 rayon（join/par_iter/专用池）与 payout-sidecar 的 JS 事件循环。

## 3. 本次修复（8 项，全部通过 check/clippy/nextest）

### 3.1 【高危】STAND_UP 持全局写锁跨 DB await
- **位置**：`texas/src/socket/handlers.rs` `handle_stand_up_local`（原 :363-402）
- **问题**：写锁块内 `state.db.unlock_chips().await`。DB 抖动期间**全服**
  所有桌的读写都被阻塞；且是仅有的两处 `state → db` 锁序嵌套之一。
- **修复**：锁内只同步收集 `chips_to_unlock: Option<(pid, stack)>`（在
  remove_player 之前读 seat.stack），块结束后锁外执行 unlock，再广播。
  复用 REBUY 路径的 `drop(gs)` 先行模式。

### 3.2 【高危】game_loop tick 清理持全局写锁跨 DB await
- **位置**：`texas/src/socket/game_loop.rs` Waiting 分支清理（原 :558-590）
- **问题**：写锁块内**循环逐玩家** `unlock_chips().await`——在 500ms 心跳
  里，DB 抖动直接冻结 game loop 并阻塞全服 socket handler。
- **修复**：块内收集 `chips_to_unlock: Vec<(String, i64)>` + 玩家移除 +
  `reset_for_next_hand()`（全同步），块外统一执行 unlock await。

### 3.3 【隐患】持写锁内 spawn consumer + 错误注释
- **位置**：`texas/src/socket/mod.rs` `init_table_event_channels`
- **问题**：写锁块内 `tokio::spawn(table_event_consumer)`。原注释"spawn
  不会立即执行 consumer，它在当前任务释放锁后才调度"在多线程 runtime 上
  **不成立**（spawn 的任务可在其他 worker 立即运行）。当前仅因 consumer
  第一步是 `rx.recv().await` 不取锁才侥幸安全——consumer 开头一旦加状态
  读取即自锁。
- **修复**：锁内只创建 channel 并注入 sender、收集 `(table_id, rx)`，锁
  释放后统一 spawn；注释改写为真实约束。

### 3.4 【隐患】game_loop panic 后 registry 残留 → 该桌永久冻结
- **位置**：`texas/src/socket/mod.rs` `start_game_loop` + `game_loop.rs` 收尾
- **问题**：`game_loop_task` 结尾的 `registry.remove` panic 时被跳过，残留
  entry 使 `start_game_loop` 的 `contains()` 永远拒绝重启（该桌永久冻结，
  动作通道成为无人消费的死通道）；`GameLoopEntry._handle` 从未被检查。
- **修复**：`GameLoopEntry` 增加 `generation`（每次启动递增）；`start_game_loop`
  spawn watchdog——`handle.await` 返回 Err（panic）时记录 error 日志并按
  generation 校验后移除残留 entry，下一动作即可自动重建 game loop。
  generation 校验防止误删 stop+restart 产生的新一代条目。

### 3.5 【隐患】action 通道 send().await 无超时 → 请求永久悬挂
- **位置**：socket/handlers.rs（RAISE）、socket/mod.rs（`send_simple_action_signed`）、
  texas/src/handlers.rs（HTTP `player_action`）
- **问题**：通道容量 100，game loop 卡死时 `send().await` 永久悬挂——这是
  "无超时等待一个可能永不消费的通道"的经典死锁形态（dev_bot 直调
  `process_action` 不走通道，不受影响）。
- **修复**：新增 `socket::send_action_with_timeout`（5s `tokio::time::timeout`
  包裹），三处发送点统一替换；超时/通道关闭向客户端返回
  `GAME_LOOP_UNRESPONSIVE`（socket emit error / HTTP 503）。

### 3.6 【隐患】结算同步 prove 占死 tokio worker
- **位置**：`texas/src/starknet/hooks.rs` `settle_hand_from_log`
- **问题**：`submit::settle_hand` 为同步 CPU 重活（prove ≈2s/手），其
  doc 自述"调用方应放在 spawn_blocking"，但调用方没照做——普通 tokio
  任务里占死一个 worker，worker 少时拖慢 tick/心跳。
- **修复**：`tokio::task::spawn_blocking` 包裹；`mirror` 移入闭包借用后
  原样带回（后续还要进 `PENDING_SETTLE`，避免整份克隆），`action_log`
  `mem::take` 所有权移入。JoinError（panic）单独记录并放行重试。

### 3.7 【高危】根 crate 跨 rayon 池阻塞（交叉池 AB-BA 形态）
- **位置**：`src/blake3_flock.rs`（`flock_pool().install` 两处）
- **问题**：全局 rayon 池 worker（orchestrator 批量 `par_iter`、组合证明
  `rayon::join`、stwo 内部 `par_iter`）经 `install` **同步阻塞**等待 64MB
  栈的 flock 专用池。当前安全仅靠"flock 库内部永不回调全局池"这一
  **未被编译器或注释强制的隐含前提**——与 39a390e 的全局锁自锁同构：
  持资源 A 等 B，而 B 的完成隐性依赖 A。flock 升级/新增回调即成实锤。
- **修复**（防护三件套，遵守"服务长跑不加 panic"原则）：
  1. flock 池线程命名 `texas-flock-N`，新增 `pub fn on_flock_pool()`；
  2. 两处 `install` 入口自检：命中重入则 `tracing::error!` **日志报警，
     不 panic**，服务继续运行、留证据排查；
  3. `flock_pool()` 文档写明跨池死锁约束（"本池任务绝不等待全局池"），
     根 crate Cargo.toml 补 `tracing` 依赖。

### 3.8 审查报告落盘
即本文档。

## 4. 复查结论：确认干净的部分

- **广播重入（39a390e 同类）全量清零**：broadcast 系列全部函数均为
  "锁内快照 → 锁释放 → emit"模式（broadcast.rs 各函数、game_loop 的
  reveal/reconstruct notice、mod.rs 的 send_shuffle_notice）；handlers.rs
  18 处 + game_loop.rs 25 处 + 其他 10 余处调用点无一持锁调用。
  handlers.rs:347 的 `drop(gs)` 是 load-bearing（防读锁重入
  `get_current_tables`），删除即死锁。
- **game_loop.rs:991 注释**记载了另一处历史死锁（锁内 await 读锁），已按
  "写锁块 → 锁外广播"模式修复，现状正确。
- **orchestrator.rs**：零锁、clone-and-replace 值语义，嵌套 rayon（par_iter
  → join → 4 路 join）为原生工作窃取用法，无死锁面。
- **静态缓存锁 4 处**：double-check + 锁外重活 + poison 安全，模式正确。
- **Table 内部事件**：`try_send` 非阻塞，排除"持锁 await 通道满 → consumer
  取锁互等"变体。
- **根 crate 其余成员**（vm-common / poker-protocol* / hand-verify-native /
  hand-bench / client-wasm）：无锁无 async，无死锁面。

## 5. 后续建议（本次明确不做）

| 项 | 位置 | 说明 |
|---|---|---|
| ZK 验证移出全局写锁 | mod.rs `submit_verified_shuffle_for_pk`/`submit_reconstruct_deck`/`join_player_and_shuffle` | BayerGroth/EC 验证在唯一的全局写锁内同步执行，所有桌被阻塞；属性能隐患，放大 3.1/3.2 类问题 |
| 分桌锁 | `SocketState.state` | 全局单锁是所有延迟类问题的根；重构动作大、行为顺序敏感，需单独立项 |
| ZK/CPU 重活的持锁窗口 | dev_bot.rs 条件性 `drop(gs)` | 显式作用域块更稳；await 距 guard 释放近，后续编辑易回归 |
| 锁粒度小项 | handlers.rs JOIN_TABLE 用写锁做只读查询；TABLE_MESSAGE 循环逐 socket 取读锁 | 锁 churn，非风险 |
| **payout-sidecar 毒丸条目**（非死锁，丢款风险） | payout-sidecar/src/queue.mjs | `deliver` 无超时 + failed 条目永久占据 dedup 键 → 赔付丢失且无法重放；建议 deliver 加超时、failed 后允许重入队 |
| **TableEvent 丢弃无兜底**（非死锁） | pokergame/table/mod.rs:524 | `try_send` 满时静默丢 `TABLE_UPDATED`/RevealNotice → 客户端失步；建议至少计数告警 |
| client-wasm 主线程冻结（非死锁） | client-wasm/src/lib.rs | 同步证明计算阻塞浏览器主线程，观感如死锁；建议走 Web Worker |
| proving-tool `rayon::broadcast` | proving-tool/src/main.rs:99 | 目前仅启动期调用，安全；加注释锚死"只能启动期调用" |

## 6. 编码规范 checklist（防复发）

1. **tokio RwLock/Mutex guard 的存活范围绝不允许包含 `.await`**——用块
   作用域 `{}` 收窄，需要跨 await 的数据在块内 clone/收集出来。
2. **持锁期间禁止调用任何"内部会取锁"的函数**（广播/emit/registry/db）；
   拿不准就看被调函数实现。广播函数自身必须"锁内快照 → 锁外 emit"。
3. **持锁块内禁止 `tokio::spawn`**——多线程 runtime 上新任务可在其他
   worker 立即运行。
4. **对可能永不消费的 channel，发送/接收必须带超时或 `try_*`**。
5. **后台任务的收尾清理（registry 移除等）必须假设 panic 会跳过它**——用
   watchdog 兜底，且带 generation/句柄校验防误删。
6. **同步 CPU 重活（>100ms）在 async 上下文中必须 `spawn_blocking`**。
7. **多线程池/多锁并存时，把"谁可以等谁"写成注释**，并为池线程命名以便
   运行时自检；自检报警用日志，不用 panic（服务长跑优先）。
8. std 锁一律 `lock().ok()` / `into_inner()` 防中毒，禁止 `unwrap()`。

## 7. 验证记录

- `cargo check -p texas -p poker_texas_air`：通过（无新增警告）
- `cargo clippy -p texas -p poker_texas_air --no-deps`：无新增告警
  （third_party/flock 的 clippy 报错为预先存在，与本次无关）
- `cargo nextest run -p texas`：84 passed, 7 skipped
- `cargo nextest run -p poker_texas_air`：259 passed, 125 skipped（慢 prove
  测试按 CI 策略 ignore）
