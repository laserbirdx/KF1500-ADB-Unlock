# KF-1500 ADB Unlock Code Generator

SDMC KF-1500 (TurksatATV / DV8957X-KTT) Android TV kutularında **Ayarlar > Cihaz Hakkında** içindeki ADB şifre kilidini açmak için seri numarasından 6 haneli kodu hesaplar.

## Algoritma

Şifre, cihazın `ro.serialno` değerinden türetilir:

```
serial  = "KFSM122800"                          # ro.serialno
plain   = serial + "ed12a270c07a58074126a0487de27f63"

key     = hex( PBKDF2-HMAC-SHA1(plain, salt="sdmc", iter=10000, dklen=16) )
          # 32 karakter hex string → 32 byte AES-256 anahtarı

ct      = AES-256/ECB/PKCS5Padding(plain, key)
b64     = Base64(ct)

code    = (b64[:3] + b64[-3:]).lower()           # → "ccabu6"
```

```
┌──────────────┐
│  Seri No     │  (ör. KFSM122800)
└──────┬───────┘
       │
       ▼
┌──────────────────────────────────────┐
│  plain = seri + sabit suffix (MD5)   │
└──────┬───────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────┐
│  PBKDF2-HMAC-SHA1                    │
│  salt="sdmc", 10000 tur, 16 byte    │
│  → hex encode → 32 char AES key     │
└──────┬───────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────┐
│  AES-256 / ECB / PKCS5Padding        │
│  encrypt(plain, key)                 │
└──────┬───────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────┐
│  Base64 encode                       │
│  ilk 3 + son 3 karakter → lowercase │
└──────┬───────────────────────────────┘
       │
       ▼
┌──────────────┐
│  6 haneli kod │  (ör. ccabu6)
└──────────────┘
```

Kaynak: `com.android.tv.settings.about` paketi içindeki `AESUtils`, `KeyGen` ve `PwdVerify` sınıfları (operatör özelleştirmeli TvSettings APK'sından decompile edildi).

## Kullanım

### GUI (çift tıkla)

```bash
python KF1500_ADB_Kod.py
```

Tkinter penceresi açılır. Seri numarasını gir, Hesapla'ya bas.

- Seri **KF** ile başlamalı ve **10 hane** olmalı
- **Ctrl+M** ile bu kısıtlamalar açılıp kapatılır (serbest giriş)

### Komut satırı

```bash
python KF1500_ADB_Kod.py KFSM122800
# KFSM122800 -> ccabu6
```

### Exe olarak derleme

```bash
pip install pyinstaller
pyinstaller --onefile --noconsole --name KF1500_ADB_Kod KF1500_ADB_Kod.py
# dist/KF1500_ADB_Kod.exe
```

## Notlar

- Harici kütüphane gerektirmez (saf Python AES-256 implementasyonu).
- `Settings.Secure "security_symbol"` ayarlıysa (≥6 karakter), hesaplanan kod yerine o değer şifre olarak kullanılır.
- ADB zaten açıksa kendi şifreni atayabilirsin: `adb shell settings put secure security_symbol SENINSIFREN`

## Lisans

MIT
