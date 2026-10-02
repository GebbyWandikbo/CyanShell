<div align="center">
  <img src="logo.png" width="500px" alt="CyanShell Logo">
</div>

<div align="center">

# 🐚 CyanShell

### Cross-Platform PHP Web Shell with Advanced Post-Exploitation Suite

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENCE)
[![PHP](https://img.shields.io/badge/PHP-7.4%2B-777BB4?logo=php&logoColor=white)](https://www.php.net/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-22d3ee)](https://github.com/)
[![Version](https://img.shields.io/badge/Version-1.4.0-blue)](https://github.com/GebbyWandikbo/CyanShell)

</div>

---

## 📖 Table of Contents

- [What It Does](#what-it-does)
- [Feature Breakdown](#feature-breakdown)
- [Usage](#usage)
- [Interface Overview](#interface-overview)
- [Advanced Operations](#advanced-operations)
- [Security & Evasion](#security--evasion)
- [Design System](#design-system)
- [Project Structure](#project-structure)
- [License](#license)
- [References](#references)

---

<a id="what-it-does"></a>

## ⚙️ What It Does

CyanShell is a **single-file PHP post-exploitation framework** that provides a modern terminal UI, robust command execution, and a suite of advanced operational tools. It is designed for authorized security testing and red team engagements.

- **No authentication.** Access to the URL equals access to the shell.
- **No dependencies.** Pure PHP + vanilla CSS/JS. Drop the file, open it, use it.
- **Cross-platform.** Auto-detects Linux vs Windows and adapts execution paths.
- **Runtime-adaptive.** Probes and falls back across 7 execution primitives automatically.
- **Feature-rich.** Built-in file manager, port scanner, PHP console, and reverse shell generator.
- **Evasion-capable.** Traffic encryption, timestomping, polymorphic builds, and self-destruct.

Two variants ship in this repo:

| File | Target | Shell |
|---|---|---|
| `cyanshell-linux.php` | Linux / Unix | `/bin/sh -c <cmd>` |
| `cyanshell-windows.php` | Windows | `cmd.exe /c <cmd>` |

---

<a id="feature-breakdown"></a>

## 🔍 Feature Breakdown

| Feature | Description |
|---|---|
| **Command Execution** | Runs OS commands via `proc_open()`. Uses `cmd.exe /c` on Windows, `/bin/sh -c` on Linux. |
| **Persistent CWD** | `cd` is handled natively and stored in `$_SESSION['cwd']`. Every later command runs in that directory. |
| **Command History** | Last 100 commands kept in session. Navigate with ↑ / ↓ arrow keys like a real shell. |
| **Function Detection** | Probes all 7 execution primitives (`proc_open`, `shell_exec`, `system`, `passthru`, `exec`, backtick, `popen`) with a live command at startup. |
| **Fallback Chain** | If the preferred function is blocked or fails mid-execution, automatically retries with the next one — no user intervention needed. |
| **FastCGI Takeover** | (Linux only) Attempts to bypass `disable_functions` by abusing PHP-FPM sockets via the FastCGI protocol. |
| **Traffic Encryption** | AES-256-CBC encryption for all command POST bodies, with PBKDF2-SHA256 key derivation. |
| **File Manager** | Integrated file browser with upload, download, edit, rename, delete, and chmod capabilities. |
| **Port Scanner** | Server-side port scanner with banner grabbing, supporting single ports, lists, and ranges. |
| **PHP Console** | Interactive PHP code execution console with output capture and fatal-error recovery. |
| **Payload Generator** | Generates reverse shell one-liners for Bash, PowerShell, Python, Perl, PHP, Netcat, Socat, and Node.js. |
| **Diagnostics Panel** | Toggleable panel (`ⓘ Diagnostics`) shows which functions are enabled, disabled, and the currently active method. |
| **Timeout Guard** | Any command that runs longer than the configured timeout is terminated with a `[timeout]` marker. |
| **Zero Install** | No composer, no build step, no config. A single `.php` file is the entire application. |

---

<a id="usage"></a>

## 🖥️ Usage

1.  Host `cyanshell-linux.php` or `cyanshell-windows.php` on a PHP-enabled web server.
2.  Open the file in a browser.
3.  Type a command in the terminal tab and press **Enter**.
4.  Use the **dropdown** to load a pre-built command from the command palette.
5.  `cd <path>` changes the session working directory.
6.  Click **ⓘ Diagnostics** in the header to inspect the environment.
7.  Use the tabs to access **Files**, **Scanner**, **PHP Console**, and **Payload** features.

The prompt always shows `user@host:/current/path$`. The header badge next to the PHP version shows the current execution method (`exec: proc_open`), or turns red (`exec: none`) if no method is available.

---

<a id="interface-overview"></a>

## 🎨 Interface Overview

The interface is organized into five main tabs, each providing a distinct capability.

### ⌨ Terminal
The primary command-and-control interface. Features command history, a persistent working directory, and a curated command palette for common tasks.

<p align="center"><img src="docs/Terminal UI.png" alt="Terminal Interface" width="800"></p>

### 📁 File Manager
A full-featured file browser. Supports uploading, downloading, editing, renaming, deleting, creating directories, and changing permissions.

<p align="center"><img src="docs/Files UI.png" alt="File Manager Interface" width="800"></p>

### &lt;/&gt; PHP Console
An interactive PHP code execution console. It allows running arbitrary PHP code in the context of the web server, with output capture and fatal-error recovery.

<p align="center"><img src="docs/PHP Console UI.png" alt="PHP Console Interface" width="800"></p>

### 💥 Payload
Generates reverse shell one-liners for various languages and platforms. Select your listener IP and port, choose a shell type, and the tool generates the command. It can also execute the payload directly on the target.

<p align="center"><img src="docs/Payload UI.png" alt="Payload Generator Interface" width="800"></p>

---

<a id="advanced-operations"></a>

## 🚀 Advanced Operations

Accessible from the header buttons, these operations are designed for post-exploitation stealth and cleanup.

| Operation | Description |
|---|---|
| **🕒 Timestomp** | Modifies the file's access and modification timestamps. It can automatically match the timestamps of a sibling file or use a manually specified date, helping to evade file-integrity monitoring. |
| **🧬 Polymorphic Build** | Generates a unique, obfuscated variant of the shell by randomizing function identifiers and adding junk comments. Each build produces a different SHA-256 fingerprint, aiding in signature evasion. |
| **☠ Self-Destruct** | Irreversibly wipes and deletes the shell file from the server, leaving no trace of the tool. It also clears client-side storage. |

<p align="center"><img src="docs/advanced-ops.png" alt="Advanced Ops Interface" width="600"></p>

---

<a id="security--evasion"></a>

## 🛡️ Security & Evasion

CyanShell includes several features designed to make detection and analysis more difficult.

| Feature | Description |
|---|---|
| **Traffic Encryption** | All command and control traffic (POST bodies) can be encrypted with AES-256-CBC. The key is derived from a user-provided passphrase using PBKDF2-SHA256 (100,000 iterations). This prevents network inspection, WAF, and IDS from reading commands in plaintext. |
| **FastCGI Takeover** | On Linux, if `disable_functions` prevents standard execution, CyanShell attempts to bypass the restriction by communicating with the PHP-FPM Unix socket directly, using the FastCGI protocol. |
| **Polymorphism** | The "Polymorphic Build" feature creates a functionally identical but syntactically unique variant of the shell on every download, defeating static signature-based detection. |
| **Timestomping** | Modifies file timestamps to blend in with legitimate files, bypassing time-based forensic analysis. |
| **Self-Destruct** | Provides a clean exit strategy by overwriting and deleting the shell file, preventing recovery and analysis. |

<p align="center"><img src="docs/encryption.png" alt="Encryption Panel" width="600"></p>

---

<a id="design-system"></a>

## 🎨 Design System

The entire UI is built with vanilla CSS — no framework, no build step. Design tokens live in `:root`:

```css
:root {
    --bg:  #0f172a;   /* base background        */
    --bg2: #1e293b;   /* elevated surfaces      */
    --cy:  #22d3ee;   /* primary accent (cyan)  */
    --gr:  #10b981;   /* prompt / success       */
    --rd:  #ef4444;   /* danger                 */
    --am:  #f59e0b;   /* warning / dropdown     */
    --tx:  #f1f5f9;   /* primary text           */
    --mu:  #64748b;   /* muted text             */
    --bd:  #475569;   /* borders                */
}
```

Notable patterns used:

| Pattern | Technique |
|---|---|
| Neon glow | `box-shadow: 0 0 16px rgba(34,211,238,.25)` |
| Ambient light | `radial-gradient` overlay on `body` |
| Scanline header | `::before` pseudo-element with linear gradient |
| Themed scrollbar | `::-webkit-scrollbar-thumb` + `:hover` |
| Custom select arrow | Inline SVG data-URI as `background-image` |
| Micro-interaction | `transform: translateY(-1px)` on button hover |
| Toggleable panel | `.diag-panel` + `.show` class toggled via `classList.toggle()` |
| Status badge | `.exec-tag` / `.exec-tag.fail` — colored inline pill next to header text |

---

<a id="project-structure"></a>

## 📁 Project Structure

```
cyanshell/
├── README.md
├── LICENCE
├── logo.png
├── docs/                      # Screenshots and documentation assets
│   ├── Terminal UI.png
│   ├── Terminal UI.png
│   ├── Exec Function Detection.png
│   ├── Files UI.png
│   ├── Payload UI.png
│   ├── PHP Console UI.png
│   ├── Polymorphic Build.png
│   ├── Scanner UI.png
│   ├── Self-Destruct.png
│   ├── Self-Destruct1.png
│   ├── Terminal UI.png
│   ├── Timestomp.png
│   ├── Timestomp1.png
│   ├── Timestomp2.png
│   ├── Timestomp3.png
│   ├── Timestomp4.png
│   └── Traffic Encryption.png
└── src/
    ├── cyanshell-linux.php      # Linux variant
    └── cyanshell-windows.php    # Windows variant
```

---

<a id="license"></a>

## 📜 License

Released under the [MIT License](LICENCE).

```
MIT License

Copyright (c) 2026 CyanShell Project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

<a id="references"></a>

## 📚 References

**Technique & Background**
- [MITRE ATT&CK — T1505.003: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK — T1059.004: Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
- [MITRE ATT&CK — T1059.003: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
- [MITRE ATT&CK — T1027: Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [MITRE ATT&CK — T1070.006: Timestomp](https://attack.mitre.org/techniques/T1070/006/)
- [OWASP — Web Shell](https://owasp.org/www-community/vulnerabilities/Web_Shell)
- [Orange Tsai, Black Hat 2019 — "Breaking Parser Logic"](https://www.blackhat.com/us-19/briefings/schedule/index.html#breaking-parser-logic-14738)

**PHP Manual**
- [`proc_open()`](https://www.php.net/manual/en/function.proc-open.php)
- [`shell_exec()`](https://www.php.net/manual/en/function.shell-exec.php)
- [`system()`](https://www.php.net/manual/en/function.system.php)
- [`passthru()`](https://www.php.net/manual/en/function.passthru.php)
- [`exec()`](https://www.php.net/manual/en/function.exec.php)
- [`popen()`](https://www.php.net/manual/en/function.popen.php)
- [`session_start()`](https://www.php.net/manual/en/function.session-start.php)
- [`htmlspecialchars()`](https://www.php.net/manual/en/function.htmlspecialchars.php)
- [PHP INI — `disable_functions`](https://www.php.net/manual/en/ini.core.php#ini.disable-functions)

**Design**
- [Tailwind Slate Palette](https://tailwindcss.com/docs/customizing-colors)
- [MDN — CSS Custom Properties](https://developer.mozilla.org/en-US/docs/Web/CSS/Using_CSS_custom_properties)

**Related Tools**
- [p0wny-shell](https://github.com/flozz/p0wny-shell) — single-file PHP shell
- [b374k](https://github.com/b374k/b374k) — feature-rich PHP shell
- [AntSword](https://github.com/AntSwordProject/antSword) — cross-platform webshell manager

---

<div align="center">

**Legal Notice** — Provided for authorized security testing and research only.
Users are responsible for complying with all applicable laws.

</div>