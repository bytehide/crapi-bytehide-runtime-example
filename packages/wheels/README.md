# ByteHide Runtime — compiled wheels

Compiled (`.so`-only) wheels of the ByteHide Runtime SDK. `Dockerfile.bh-python` detects the
container's libc and installs the matching wheel; pip then picks the right CPU architecture.

The crAPI Python services fix the interpreter, so only **two variables** matter:

- **libc** — fixed by the base image: `crapi-workshop` is Alpine (**musl**), `crapi-chatbot` is Debian (**glibc**).
- **architecture** — set by the machine that runs `docker compose`: Intel/AMD (**x86_64**) or ARM/Apple Silicon (**aarch64**).

Python is always **cp311** (both services run Python 3.11).

```
wheels/
├─ glibc/   # for crapi-chatbot (Debian)
│  ├─ bytehide_monitor-0.1.0-cp311-cp311-linux_x86_64.whl
│  └─ bytehide_monitor-0.1.0-cp311-cp311-linux_aarch64.whl
└─ musl/    # for crapi-workshop (Alpine)
   ├─ bytehide_monitor-0.1.0-cp311-cp311-linux_x86_64.whl
   └─ bytehide_monitor-0.1.0-cp311-cp311-linux_aarch64.whl
```

Shipping both architectures in each folder makes the bundle work on any client machine (x86_64 or ARM).
