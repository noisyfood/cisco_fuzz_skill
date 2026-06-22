# IoT Fuzz Skill

This skill is using for IoT devices such as Cisco IOS XE serials devices vulnerabilities discovery. The skill employ libafl as fuzz toolkit, training on fuzzing101 project and several private Cisco vulnerabilities.

# Quick Start

Libafl environment is needed:

```bash
git clone https://github.com/AFLplusplus/LibAFL
cargo build --release
```

Then follow `LibAFL/bindings/pylibafl` for python bindings. What's more, IDA Pro MCP or other equal tools for reverse are needed.
