<p align="center">
  <img src="banner.webp" alt="KF1500 ADB Unlock" width="100%">
</p>

# KF-1500 ADB Unlock Code Generator

Computes the 6-digit unlock code for the ADB password gate on SDMC KF-1500 (TurksatATV / DV8957X-KTT) Android TV boxes. The code is derived from the device serial number (`ro.serialno`).

## Device Specifications

| Field              | Value                                           |
|--------------------|------------------------------------------------|
| Model / Device     | KF-1500 / DV8957X-KTT (TurksatATV-23)         |
| Manufacturer       | SDMC / TVHerYerde                               |
| SoC                | Amlogic S905X4 (platform `ohm`), 4x Cortex-A55 |
| ABI                | armeabi-v7a (32-bit userspace)                  |
| RAM                | 3.7 GB                                          |
| Storage (/data)    | 25 GB                                           |
| Android            | 12 (SDK 31), build `20241011`                   |
| Security Patch     | 2024-09-05                                      |
| Kernel             | 5.4.242-android12-9                             |
| Display            | 3840x2160 (override 1920x1080, 320 dpi)        |
| Serial Format      | KFSMxxxxxx (10 characters)                      |

## Algorithm

The password is derived from the device's `ro.serialno` value:

```
serial = "KFXX111111"                            # ro.serialno
plain  = serial + "ed12a270c07a58074126a0487de27f63"

key    = hex( PBKDF2-HMAC-SHA1(plain, salt="sdmc", iter=10000, dklen=16) )
         # 32-char hex string -> 32-byte AES-256 key

ct     = AES-256/ECB/PKCS5Padding(plain, key)
b64    = Base64(ct)

code   = (b64[:3] + b64[-3:]).lower()            # -> "ujasy4"
```

```
          ┌────────────────────┐
          │   Serial Number    │
          └─────────┬──────────┘
                    │
                    ▼
┌────────────────────────────────────────┐
│  plain = serial + fixed suffix (MD5)   │
└────────────────────┬───────────────────┘
                     │
                     ▼
┌────────────────────────────────────────┐
│  PBKDF2-HMAC-SHA1                      │
│  salt="sdmc", 10000 iter, 16 bytes     │
│  -> hex encode -> 32-char AES key      │
└────────────────────┬───────────────────┘
                     │
                     ▼
┌────────────────────────────────────────┐
│  AES-256 / ECB / PKCS5Padding          │
│  encrypt(plain, key)                   │
└────────────────────┬───────────────────┘
                     │
                     ▼
┌────────────────────────────────────────┐
│  Base64 encode                         │
│  first 3 + last 3 chars -> lowercase   │
└────────────────────┬───────────────────┘
                     │
                     ▼
          ┌────────────────────┐
          │    6-digit code    │
          └────────────────────┘
```

Source: `AESUtils`, `KeyGen` and `PwdVerify` classes in the `com.android.tv.settings.about` package (decompiled from the operator-customized TvSettings APK).

## Usage

### GUI (double-click)

```bash
python KF1500_ADB_Kod.py
```

Opens a Tkinter window. Enter the serial number and click Calculate.

- Serial must start with **KF** and be exactly **10 characters**

### Command Line

```bash
python KF1500_ADB_Kod.py KFXX111111
# KFXX111111 -> ujasy4
```

### Build as Exe

```bash
pip install pyinstaller
pyinstaller --onefile --noconsole --name KF1500_ADB_Kod KF1500_ADB_Kod.py
# dist/KF1500_ADB_Kod.exe
```

## Notes

- Zero external dependencies (pure Python AES-256 implementation).
- If `Settings.Secure "security_symbol"` is set (>= 6 chars), that value overrides the computed code.
- If ADB is already enabled, you can set your own password: `adb shell settings put secure security_symbol YOURPASSWORD`

## Acknowledgements

- [@MATTAM540](https://github.com/MATTAM540) — thanks for the inspiration and contributions.

## License

MIT — see [LICENSE](LICENSE) for details.
