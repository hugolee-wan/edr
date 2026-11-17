VNB EDR (vnb-security-assistant)

跨平台终端检测与响应 (EDR) 系统 · Cross-platform Endpoint Detection and Response (EDR) Agent & Workbench
简体中文 | English · C-ABI 0x00020300 · Rust 2021 · License: MIT OR Apache-2.0

中文说明
项目简介

vnb-security-assistant 是基于 Rust 构建的跨平台终端检测与响应（EDR）代理与桌面工作台，支持 macOS（GPUI 原生桌面界面）、Windows（eframe/egui 桌面界面） 以及 Linux/macOS/Windows 无头 CLI、守护进程与 C-ABI 共享库。

系统默认可完全离线运行，集成主机实时遥测、本地轻量安全分类模型、主机防火墙与网络载荷检测、策略化响应与可回滚文件隔离功能，并可选接入 OpenAI 兼容大模型接口（或本地 CLI 网关）对高风险告警进行二次研判。

核心功能

终端遥测与实体关联

进程与血缘追踪：采集进程列表、父子进程链、命令行参数、工作目录（CWD）、代码签名状态、文件 SHA-256 哈希及加载模块。
持久化与自启动审计：检查 macOS LaunchAgents / LaunchDaemons / cron 与 Windows 注册表 Run 键 / 计划任务。
网络连接与端口暴露：监控活跃 TCP/UDP 监听与外联会话，识别 0.0.0.0 全网卡暴露端口与异常外联目标。
文件完整性与凭据监控（FIM）：监测临时目录高风险可执行落盘及敏感凭据文件权限异常。
桌面弹窗与广告程序清理：识别异常置顶广告弹窗及浏览器扩展/Adware 残留，支持在保留正常宿主应用文档的前提下关闭弹窗并按规则拦截恶意域名（adblock_hosts.rules）。

本地模型检测与可选 LLM 复核

离线本地推理（models/）：
models/qwen25_security_model.safetensors（约 39 MB）：基于 Apache-2.0 开源的 Qwen/Qwen2.5-Coder-1.5B-Instruct 提取前 4 层 Transformer（1536-D）与 BPE 词表（models/qwen25_bpe_vocab.json，478 KB），并结合安全分类头、残差决策网络与弹窗广告分类头。
LightGBM 安全决策森林：edr_moe_gating_router.txt 与 8 组专项安全规则树（edr_forest_*.txt，覆盖进程血缘、网络连接、持久化、凭据 FIM、高熵落盘、内存注入、全网卡暴露、弹窗广告）及校准表 edr_leaf_calibration.bin。
可选大模型复核：支持通过 edr_model_config.json 对接本地网关或任意 OpenAI /v1/chat/completions 接口与 CLI 工具；当外部接口不可达时自动回退至离线本地判定。

主机防火墙、载荷检测与威胁情报

主机防火墙与 IPS：管理本机入/出站阻断规则并同步至系统防火墙（macOS pfctl / Windows netsh），内置网络载荷检测引擎用于识别常见反弹 Shell、Shellcode 模式、隐蔽 Base64 外传隧道与未授权服务命令注入。
威胁情报联查：计算样本 SHA-256 与 SimHash-64 结构相似度，通过 vnb_threat_intel_config.json 支持内置离线 IOC 库，以及可选配置 AlienVault OTX、abuse.ch ThreatFox、VirusTotal v3 或自定义 REST 情报源。

分级响应策略、安全护栏与可回滚隔离

确定性响应策略矩阵：按威胁类型、风险等级（L1–L4）与主机上下文生成审计计划，支持放行加白、告警待审、关闭弹窗不伤及宿主、先挂起进程树（SIGSTOP / Win32 Suspend）再逐级终止以防互保重启、卸载启动项与移入隔离区。
防逃逸与一键回滚：对查杀样本同时记录路径与 SHA-256 阻止再次拉起；每次文件隔离生成回执，支持将隔离文件还原至原路径并同步解除阻止。
内置安全护栏：默认开启关键系统进程与自身进程保护（protect_critical_system_hosts）、活跃文档应用保护（protect_active_document_hosts），并提供演练模式（dry_run_mode）与单轮自动终止上限（max_auto_kills_per_cycle）。

跨平台桌面工作台与响应式布局

macOS 原生工作台（GPUI）：采用非阻塞冷启动，支持左侧导航栏、中间主表格、右侧详情/处置面板与底部实时日志抽屉四区自由拖拽调整大小，支持边缘磁吸折叠、双击分隔条重置布局及面板卡片独立展开/收起。
Windows 原生工作台（eframe/egui）：基于 Win32 原生 API 实现进程、网络、注册表、防火墙、弹窗与日志排查界面。
系统架构
目录结构
text
./
├── Cargo.toml                         # Rust 工程配置 (MIT OR Apache-2.0)
├── Cargo.lock                         # 离线依赖锁定文件
├── LICENSE-MIT / LICENSE-APACHE       # 源码双重开源协议文本
├── NOTICE                             # 模型权重与训练树归属声明
├── edr_model_config.json              # 默认模型与可选大模型复核配置
├── vnb_threat_intel_config.json       # 默认威胁情报源与 IOC 配置模板
├── lib/
│   └── libvnb_edr_gpui.dylib          # 编译产物：核心 EDR 引擎与 UI 的 C-ABI 共享库
├── models/
│   ├── qwen25_security_model.safetensors  # 基于 Qwen2.5-Coder 提取的安全分类模型 (Apache-2.0)
│   ├── qwen25_bpe_vocab.json              # 32,768 词表 BPE 分词文件
│   ├── edr_moe_gating_router.txt          # 安全领域 MoE 门控树
│   ├── edr_forest_*.txt                   # 8 组专项安全 LightGBM 决策森林
│   └── edr_leaf_calibration.bin           # 模型输出校准表
├── scripts/
│   └── build_dylib_thin.sh            # macOS 共享库编译、路径脱敏与签名封装脚本
└── src/
    ├── lib.rs                         # C-ABI 导出接口 (v0x0002_0300) 与 CLI 调度入口
    ├── main.rs                        # 动态库宿主入口与集成测试
    ├── edr_engine.rs                  # EDR 核心状态机、异步采集与告警关联引擎
    ├── remediation_matrix.rs          # 风险分级矩阵与防误杀护栏策略
    ├── firewall_ips.rs                # 主机防火墙与网络载荷检测模块
    ├── threat_intel.rs                # 样本哈希/SimHash 匹配与情报源联查
    ├── ad_blocker.rs                  # 桌面弹窗清理、Adware 检测与 Hosts 规则管理
    ├── pretrained_models.rs           # Safetensors / BPE / LightGBM 本地推理运行时
    ├── gpui_edr.rs / ui.rs            # macOS (GPUI) 与 Windows (eframe/egui) 桌面工作台
    ├── bin/vnb_build_models.rs        # 纯 Rust 本地模型权重提取与决策树重训工具
    ├── bin/vnb_rogue_target.rs        # 受控测试靶标（用于沙箱验证检测能力）
    └── ...                            # 其余跨平台系统遥测、隔离执行与契约模块
快速开始与命令行模式
1. 启动图形界面（macOS）
zsh
open "./VNB终端安全助手.app"
# 或直接运行命令行宿主启动器：
./vnb-security-assistant
2. 命令行与守护进程模式
参数	说明	是否生成本地状态/日志文件
--abi-info	输出 JSON 格式的 ABI 版本（0x0002_0300）、硬件规格与模型加载摘要	否
--headless-check / --edr-scan	无界面执行一次完整终端扫描、载荷检测自检与策略评估，输出结构化 JSON	是
--daemon	常驻后台守护模式，按主机硬件档位自适应周期轮询检测并记录审计日志	是
--low-spec / --software-render	低配/节能模式，降低采样频率与界面渲染密度	视主模式而定

常用环境变量：

VNB_HOME=<path>：指定应用根目录（用于查找 lib/ 与 models/）。
VNB_LOW_SPEC=1：等效于启用 --low-spec。
从源码构建与测试

前置要求：Rust 工具链（Edition 2021）；macOS 需 Xcode Command Line Tools；Windows 跨平台构建/检查需 x86_64-pc-windows-msvc 目标。模型构建器已全部采用 Rust 实现，无需 Python 环境。

zsh
# 1. 运行离线单元测试与集成测试
cargo test --offline
# 2. macOS 构建精简共享库、脱敏路径、重签并更新宿主可执行文件
./scripts/build_dylib_thin.sh
# 3. 交叉检查 Windows 目标兼容性
cargo check --offline --target x86_64-pc-windows-msvc --all-targets
# 4. 校验共享库 ABI 与运行能力（无副作用）
./vnb-security-assistant --abi-info
# 5. (可选) 重新生成 models/ 下的本地权重与安全决策森林
cargo run --release --offline --bin vnb-build-models
配置文件与 C-ABI 接口
1. 配置文件（应用根目录）
edr_model_config.json：配置 decision_mode（本地或 HTTP 决策接口）、reasoning_mode（NetworkHttpChat 对接兼容 OpenAI /v1/chat/completions 接口，或 SimpleCliGateway 调用本地 CLI）、超时时间、温度阈值与自定义系统提示词。
vnb_threat_intel_config.json：管理内置离线 IOC 库及 AlienVault OTX（X-OTX-API-KEY）、abuse.ch ThreatFox（Auth-Key）、VirusTotal v3（x-apikey）或自定义 REST 接口的启用状态、权重与自定义 IOC 列表。
2. C-ABI 共享库接口 (libvnb_edr_gpui)

src/lib.rs 导出以下 9 个 extern "C" 函数（由共享库返回的字符串指针均需调用 vnb_edr_free_string 释放）：

函数符号	说明
vnb_edr_abi_version() -> u32	返回 C-ABI 版本号（0x0002_0300）
vnb_edr_runtime_caps_json() -> *mut c_char	返回宿主机硬件档位、动态库及模型摘要 JSON
vnb_edr_engine_create() -> *mut c_void	创建无头沙盒引擎实例（不写入磁盘日志）并执行初始扫描
vnb_edr_engine_destroy(handle)	销毁引擎实例并释放资源
vnb_edr_engine_scan_and_summary_json(handle) -> *mut c_char	执行轻量扫描并返回进程、网络、告警、防火墙与情报摘要 JSON
vnb_edr_engine_investigate_json(handle, target_utf8) -> *mut c_char	对指定 IP、文件路径或 Hash 执行关联调查并返回报告 JSON
vnb_edr_t5b8_inspect_json(ptr, len, proc, lport, rport, wildcard) -> *mut c_char	无状态函数：检测网络载荷字节流并返回异常判定 JSON
vnb_edr_run_from_cli() -> i32	共用标准 CLI / GUI 启动分发入口
vnb_edr_free_string(ptr)	释放由 vnb_edr_* 分配返回的 C 字符串

Python ctypes 调用示例：

python
import ctypes, json
lib = ctypes.CDLL("./lib/libvnb_edr_gpui.dylib")
lib.vnb_edr_abi_version.restype = ctypes.c_uint32
lib.vnb_edr_runtime_caps_json.restype = ctypes.c_void_p
lib.vnb_edr_free_string.argtypes = [ctypes.c_void_p]
print(f"ABI Version: 0x{lib.vnb_edr_abi_version():08x}")
ptr = lib.vnb_edr_runtime_caps_json()
try:
    caps = json.loads(ctypes.cast(ptr, ctypes.c_char_p).value.decode("utf-8"))
    print("Engine Caps:", caps["abi_version"], caps["hardware_profile"])
finally:
    lib.vnb_edr_free_string(ptr)
隐私说明、安全建议与开源协议
本地优先与零默认外传：审计日志（edr_audit.log）、事件记录（edr_history.jsonl）、防火墙状态（vnb_firewall_ips.json）与 Hosts 规则（adblock_hosts.rules）均仅写入本地目录；不会主动上报主机遥测，仅在用户显式配置外部情报 API Key 或远程大模型地址后才发起对应请求。
生产部署建议：首次部署至生产主机时建议先开启演练模式（dry_run_mode），并保持关键系统进程与活跃文档宿主护栏开启。src/bin/vnb_rogue_target.rs 仅用于在授权测试环境验证检测链路。
开源许可：源码与构建脚本采用 MIT OR Apache-2.0 双重许可；models/ 下的模型权重与安全决策森林采用 Apache-2.0 许可，详见 NOTICE。
English
Overview

vnb-security-assistant (VNB EDR) is a cross-platform Endpoint Detection and Response (EDR) agent and desktop workbench written in Rust. It supports macOS (native GPUI desktop application), Windows (eframe/egui desktop UI and Win32 telemetry), and Linux/macOS/Windows headless CLI, background daemon, and C-ABI shared library integration.

Designed to run 100% offline by default, VNB EDR combines real-time endpoint telemetry, on-device security ML models, host firewall and network payload inspection, policy-driven response with reversible quarantine, and optional secondary alert review via any OpenAI-compatible LLM endpoint or local CLI gateway.

Key Features

Endpoint Telemetry & Entity Correlation

Process & Lineage Inspection: Collects live processes, parent-child ancestry, command lines, current working directories (CWD), code-signing status, SHA-256 file digests, and loaded modules.
Persistence & Autostart Auditing: Scans macOS LaunchAgents / LaunchDaemons / cron and Windows Registry Run keys / Scheduled Tasks.
Network & Exposure Monitoring: Inspects active TCP/UDP sockets, highlights 0.0.0.0 wildcard bindings, and tracks outbound connections.
File Integrity & Credential Monitoring (FIM): Flags unexpected executables dropped into temporary directories and overly permissive credential/SSH files.
Popup & Adware Cleanup: Identifies intrusive desktop popup windows and adware/extension leftovers, allowing popup dismissal without terminating legitimate host applications alongside domain rule blocking (adblock_hosts.rules).

On-Device Detection Models & Optional LLM Review

Local Inference Bundle (models/):
models/qwen25_security_model.safetensors (~39 MB): First 4 Transformer layers (1536-D) and BPE vocabulary (models/qwen25_bpe_vocab.json, 478 KB) derived from Apache-2.0 Qwen/Qwen2.5-Coder-1.5B-Instruct, paired with security classification heads, a residual risk network, and a popup/adware classifier.
LightGBM Security Ensembles: A routing classifier (edr_moe_gating_router.txt) plus 8 domain-specific security decision forests (edr_forest_*.txt covering process lineage, network C2, persistence, credential FIM, temp droppers, memory injection, wildcard exposure, and popups) with calibration data (edr_leaf_calibration.bin).
Optional External Review: Connects via edr_model_config.json to any OpenAI /v1/chat/completions compatible endpoint or local CLI gateway for secondary alert analysis, automatically falling back to offline local models when disconnected.

Host Firewall, Payload Inspection & Threat Intelligence

Host Firewall & IPS: Manages inbound/outbound IP and port rules synchronized with the OS firewall (pfctl on macOS, netsh on Windows) and inspects network payloads for reverse shells, shellcode sequences, covert Base64 tunnels, and unauthorized service commands.
Threat Intelligence Lookup: Computes SHA-256 and SimHash-64 similarity fingerprints and queries configurable feeds in vnb_threat_intel_config.json (built-in offline IOC database, AlienVault OTX, abuse.ch ThreatFox, VirusTotal v3, and custom REST endpoints).

Policy Matrix, Safety Guardrails & Reversible Quarantine

Risk-Tiered Response Policy: Evaluates findings across threat categories, severity tiers (L1–L4), and host context to apply allowlisting, alert review, non-destructive popup dismissal, suspend-before-terminate process tree cleanup (SIGSTOP / Win32 Suspend to prevent watchdog respawns), persistence removal, and file quarantine.
Anti-Respawn & Rollback: Records both file path and SHA-256 execution blocks when isolating binaries; each quarantine action produces a receipt supporting one-click restoration and unblock.
Built-in Guardrails: Enforces critical OS/self-process protection (protect_critical_system_hosts), active document host protection (protect_active_document_hosts), dry-run simulation (dry_run_mode), and per-cycle auto-termination limits (max_auto_kills_per_cycle).

Desktop Workbench UX

macOS (gpui_edr.rs): Non-blocking startup with a 4-zone resizable split layout (left sidebar, main table, right inspector/actions panel, bottom live log drawer), snap-to-collapse splitters, double-click layout reset, and collapsible cards.
Windows (ui.rs): Native Win32 workbench built with eframe/egui.
Architecture
Telemetry & OS Primitives: Cross-platform process, socket, persistence, FIM, window, and firewall adapters.
Detection & Intelligence: On-device safetensors + LightGBM inference, network payload inspection, SHA-256/SimHash-64 matching, offline/online IOC feeds, and optional LLM gateway integration.
Policy & Guardrails: Deterministic risk evaluation (L1–L4), system/document protection, dry-run validation, and per-cycle rate limiting.
Response & Recovery: Process-tree suspension and termination, OS persistence/firewall enforcement, local quarantine vault, and rollback support.
Interfaces: macOS GPUI app, Windows egui app, CLI/daemon modes, and a v0x0002_0300 C-ABI shared library.
Repository Structure
text
./
├── Cargo.toml                         # Rust manifest (MIT OR Apache-2.0)
├── Cargo.lock                         # Offline dependency lockfile
├── LICENSE-MIT / LICENSE-APACHE       # Dual license texts
├── NOTICE                             # Attribution notice for derived weights and security trees
├── edr_model_config.json              # Default model & optional LLM endpoint configuration
├── vnb_threat_intel_config.json       # Default threat intelligence feed & IOC configuration
├── lib/
│   └── libvnb_edr_gpui.dylib          # Built C-ABI shared library containing engine & UI
├── models/
│   ├── qwen25_security_model.safetensors  # Qwen2.5-Coder derived security classifier (Apache-2.0)
│   ├── qwen25_bpe_vocab.json              # 32,768-token BPE vocabulary
│   ├── edr_moe_gating_router.txt          # Security MoE gating LightGBM ensemble
│   ├── edr_forest_*.txt                   # 8 domain-specific security LightGBM forests
│   └── edr_leaf_calibration.bin           # Model output calibration table
├── scripts/
│   └── build_dylib_thin.sh            # macOS release build, path-remapping & codesign script
└── src/
    ├── lib.rs                         # C-ABI v0x0002_0300 exports & CLI entrypoint
    ├── main.rs                        # Thin host executable & integration test suite
    ├── edr_engine.rs                  # Core EDR state machine, async scan & correlation engine
    ├── remediation_matrix.rs          # Risk-tiered policy matrix & safety guardrails
    ├── firewall_ips.rs                # Host firewall manager & network payload inspector
    ├── threat_intel.rs                # Hash/SimHash matching & multi-feed threat intel client
    ├── ad_blocker.rs                  # Desktop popup cleanup, adware detection & hosts rules
    ├── pretrained_models.rs           # Pure-Rust safetensors / BPE / LightGBM runtime
    ├── gpui_edr.rs / ui.rs            # macOS (GPUI) & Windows (eframe/egui) desktop UI
    ├── bin/vnb_build_models.rs        # Pure-Rust model extractor & security tree trainer
    ├── bin/vnb_rogue_target.rs        # Controlled sandbox target for detection verification
    └── ...                            # Platform telemetry, containment/quarantine & contract modules
Quick Start & CLI Modes
Launch Desktop Workbench (macOS)
zsh
open "./VNB终端安全助手.app"
# Or run the thin host binary directly:
./vnb-security-assistant
CLI & Daemon Options
Flag	Description	Writes State/Log Files
--abi-info	Prints JSON metadata for C-ABI version (0x0002_0300), host profile, and loaded models	No
--headless-check / --edr-scan	Runs full endpoint telemetry, payload self-checks, and policy evaluation; outputs JSON	Yes
--daemon	Runs as a background agent polling at hardware-adaptive intervals	Yes
--low-spec / --software-render	Reduces polling rate and UI row density for low-memory hosts or VMs	Depends on mode

Environment variables:

VNB_HOME=<path>: Overrides the application root directory used to locate lib/ and models/.
VNB_LOW_SPEC=1: Equivalent to --low-spec.
Building & Testing from Source

Prerequisites: Rust toolchain (2021 edition); Xcode Command Line Tools on macOS; x86_64-pc-windows-msvc target for Windows builds/cross-checks. No Python environment is required (vnb-build-models is pure Rust).

zsh
# 1. Run offline unit and end-to-end tests
cargo test --offline
# 2. Build shared library, strip debug symbols, remap build paths, and codesign (macOS)
./scripts/build_dylib_thin.sh
# 3. Verify Windows target compilation
cargo check --offline --target x86_64-pc-windows-msvc --all-targets
# 4. Inspect C-ABI and runtime capabilities (read-only)
./vnb-security-assistant --abi-info
# 5. (Optional) Rebuild on-device weights & LightGBM security forests in models/
cargo run --release --offline --bin vnb-build-models
Configuration & C-ABI FFI
Configuration Files
edr_model_config.json: Controls local vs. HTTP decision mode, optional OpenAI /v1/chat/completions or CLI secondary review (reasoning_mode), timeouts, temperature, and prompt settings.
vnb_threat_intel_config.json: Configures the built-in offline IOC vault alongside optional AlienVault OTX (X-OTX-API-KEY), abuse.ch ThreatFox (Auth-Key), VirusTotal v3 (x-apikey), and custom REST feeds.
C-ABI Exports (libvnb_edr_gpui)

src/lib.rs exports 9 stable extern "C" functions (free all returned string pointers with vnb_edr_free_string):

Symbol	Description
vnb_edr_abi_version() -> u32	Returns ABI version (0x0002_0300)
vnb_edr_runtime_caps_json() -> *mut c_char	Returns hardware profile, shared library status, and model summary as JSON
vnb_edr_engine_create() -> *mut c_void	Creates a sandboxed headless engine instance (no disk writes) and runs an initial scan
vnb_edr_engine_destroy(handle)	Destroys an engine handle created by vnb_edr_engine_create
vnb_edr_engine_scan_and_summary_json(handle) -> *mut c_char	Runs a lightweight telemetry pass and returns JSON summary counts
vnb_edr_engine_investigate_json(handle, target_utf8) -> *mut c_char	Investigates a target IP, file path, or hash and returns a JSON report
vnb_edr_t5b8_inspect_json(ptr, len, proc, lport, rport, wildcard) -> *mut c_char	Stateless payload inspection for anomaly/attack classification as JSON
vnb_edr_run_from_cli() -> i32	Runs the unified CLI / GUI host entrypoint
vnb_edr_free_string(ptr)	Frees C strings returned by vnb_edr_* functions

Python ctypes example:

python
import ctypes, json
lib = ctypes.CDLL("./lib/libvnb_edr_gpui.dylib")
lib.vnb_edr_abi_version.restype = ctypes.c_uint32
lib.vnb_edr_runtime_caps_json.restype = ctypes.c_void_p
lib.vnb_edr_free_string.argtypes = [ctypes.c_void_p]
print(f"ABI Version: 0x{lib.vnb_edr_abi_version():08x}")
ptr = lib.vnb_edr_runtime_caps_json()
try:
    caps = json.loads(ctypes.cast(ptr, ctypes.c_char_p).value.decode("utf-8"))
    print("Engine Caps:", caps["abi_version"], caps["hardware_profile"])
finally:
    lib.vnb_edr_free_string(ptr)
Privacy, Safety Guardrails & License
Local-First by Default: Audit logs (edr_audit.log), event history (edr_history.jsonl), firewall rules (vnb_firewall_ips.json), and hosts rules (adblock_hosts.rules) remain in the local working directory. No telemetry is uploaded; external requests occur only if you explicitly enable third-party threat intel or remote LLM endpoints.
Production Rollout: Enable dry_run_mode first when onboarding new production hosts, and keep critical system and active-document guardrails enabled. src/bin/vnb_rogue_target.rs is solely for authorized test sandboxes.
License: Source code and documentation are dual-licensed under MIT OR Apache-2.0. Pretrained and derived model files under models/ are licensed under Apache-2.0 (see NOTICE).
