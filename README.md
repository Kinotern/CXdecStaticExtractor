# CXdecStaticExtractor (Rust & Tauri Version)

**CXdecStaticExtractor** 是一款专为 Kirikiri/Krkrz 引擎的 HXV4 静态加密体系（常见于 YuzuSoft、HikariField 等发行的视觉小说游戏）量身定制的本地静态解密与解包工具。本项目使用 Rust 与 Tauri 进行重构，提供了极高的提取性能与现代化的跨平台 GUI 界面。

## 核心功能

*   **现代化图形界面 (GUI)**：基于 Tauri 与 HTML5/JS/CSS 构建，界面轻量、响应迅速，支持可视化的方案库管理和解包任务队列。
*   **极速并行解包**：基于 Rust 底层重构，采用 `rayon` 并行计算库，多线程并发提取与解密，解包速度达到硬件极限。
*   **PE 静态解密分析器**：内置 `cxdec-rs-analyzer` 命令行工具，可静态分析游戏可执行文件并提取出底层加密流虚拟机数据（DRIP Bytecode）和密钥方案。
*   **数据瘦身优化**：采用 `JSON + BIN` 混合存储方案。将庞大的过滤器运行流数据以紧凑的二进制格式 (`.bin`) 存储，元数据以极简 JSON 存储，大幅提升加载解析性能，避免大整数溢出问题。

## 目录结构

*   [`src-tauri/`](file:///src-tauri) —— Tauri GUI 程序的 Rust 后端，负责解包队列调度、HXV4 算法实现以及 XP3 文件流解析。
*   [`ui/`](file:///ui) —— GUI 程序的前端代码（采用纯 Vanilla HTML / CSS / JavaScript 构建，无需复杂的打包构建流程）。
*   [`cxdec-rs-analyzer/`](file:///cxdec-rs-analyzer) —— 独立的 PE 静态分析 CLI 工具，用于从游戏可执行文件中提取解密方案信息。
*   [`scheme/`](file:///scheme) —— 方案配置库存放目录。存放各个游戏及版本的 `.json` 配置文件、`.bin` 虚拟机字节码文件和 `.lst` 文件名碰撞列表。

## 快速开始

### 1. 开发与构建环境准备

在开始构建前，请确保您的系统已安装了以下基础工具：
*   **Rust 编译链**：[安装 Rust](https://www.rust-lang.org/tools/install)（推荐安装最新稳定版，本项目的 `cxdec-rs-analyzer` 使用了 `2024` edition）。
*   **Tauri CLI**：您可以通过 Cargo 安装 Tauri 命令行工具：
    ```bash
    cargo install tauri-cli --version "^1.5"
    ```

---

### 2. 构建与运行 GUI 界面

#### 开发模式运行
在根目录下直接启动 Tauri 开发服务器：
```bash
cargo tauri dev
```
此命令会自动加载前端项目并启动调试窗口。

#### 生产打包构建
生成独立运行的 Release 版本安装包与可执行程序：
```bash
cargo tauri build
```
打包成功后，编译产物将会保存在 `src-tauri/target/release/` 下。

---

### 3. 使用 PE 静态分析器 (`cxdec-rs-analyzer`)

如果您需要针对未录入的新游戏进行静态解密分析并导出方案，可以使用 `cxdec-rs-analyzer`。

```bash
cargo run --manifest-path cxdec-rs-analyzer/Cargo.toml -- --exe <游戏EXE路径> --work-dir <游戏工作目录> --out <导出方案输出目录>
```

#### 参数说明
*   `--exe`：目标游戏的运行可执行文件（`.exe`）路径。
*   `--work-dir`：游戏所在的根目录，分析器将在此目录查找关联资源与提取元数据。
*   `--out`：分析完毕后，生成的 `_scheme.json` 以及 `_drip_program.bin` 等配置的导出路径。

---

## 方案 (Scheme) 目录规范说明

每一个解密方案文件夹中需要包含以下几类文件以确保解密核心正常工作：
1.  **`[方案名]_scheme.json`**：方案的元数据配置，包含游戏名称、发行商、版本、以及 HXV4 加密所需的 32 字节 key 和 nonce 等关键参数。
2.  **`[方案名]_drip_program.bin`**：过滤器虚拟机（Drip Value VM）的流水线流数据（DRIP Bytecode），以紧凑二进制存储以提升读取效率。
3.  **`[方案名]_drip_program.json`**：过滤程序的一些元数据（如大小、配置项），剔除了冗长的数组。
4.  **`*.lst` (可选)**：游戏原始文件名列表，用于碰撞被 Hash 混淆过的 `.xp3` 封包文件名，以恢复原本的文件夹树目录结构。

## 许可证

本项目采用 [GNU Affero General Public License v3 (AGPL-3.0)](file:///LICENSE) 许可证开源。