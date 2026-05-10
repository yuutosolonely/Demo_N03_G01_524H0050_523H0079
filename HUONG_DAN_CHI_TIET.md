# 📘 HƯỚNG DẪN CHI TIẾT DỰ ÁN DIGITAL SIGNATURE TOOL (v2.0)

## Mục lục
1. [Tổng quan dự án](#1-tổng-quan-dự-án)
2. [Kiến thức nền tảng cần nắm](#2-kiến-thức-nền-tảng-cần-nắm)
3. [Kiến trúc hệ thống](#3-kiến-trúc-hệ-thống)
4. [Chi tiết từng Module](#4-chi-tiết-từng-module)
5. [Luồng hoạt động (Workflow)](#5-luồng-hoạt-động-workflow)
6. [Flask Backend — Giải thích từng Route](#6-flask-backend--giải-thích-từng-route)
7. [Frontend — Giao diện người dùng](#7-frontend--giao-diện-người-dùng)
8. [Các kịch bản Demo quan trọng](#8-các-kịch-bản-demo-quan-trọng)
9. [Câu hỏi thường gặp khi thuyết trình](#9-câu-hỏi-thường-gặp-khi-thuyết-trình)
10. [Cách chạy dự án](#10-cách-chạy-dự-án)

---

## 1. Tổng quan dự án

### Dự án làm gì?
Đây là một **công cụ ký số (Digital Signature Tool)** cho file PDF, gồm 3 vai trò:

| Vai trò | Chức năng |
|---------|-----------|
| **Sender (Người gửi)** | Tạo cặp khóa RSA/ECDSA → Ký file PDF → Xuất file `.sigbundle` |
| **Receiver (Người nhận)** | Nhận file `.sigbundle` → Xác minh chữ ký → Phát hiện giả mạo |
| **Attacker (Demo tấn công)** | Sửa 1 byte trong PDF hoặc tái sử dụng chữ ký → Chứng minh hệ thống phát hiện được |

### Công nghệ sử dụng

| Thành phần | Công nghệ | Lý do chọn |
|-----------|-----------|-------------|
| Backend | **Python + Flask** | Dễ hiểu, có thư viện crypto mạnh |
| Mật mã | **cryptography** (thư viện Python) | Hỗ trợ RSA-PSS, ECDSA, SHA-256 chuẩn công nghiệp |
| Frontend | **HTML/CSS/JS + SweetAlert2** | Giao diện đẹp cho demo |
| Đóng gói | **ZIP (.sigbundle)** | Đóng gói PDF + chữ ký + public key + metadata |

### Cấu trúc thư mục

```
digital-signature-tool/
├── app.py                    ← Flask server (điều phối mọi thứ)
├── requirements.txt          ← Thư viện cần cài
├── test_all.py               ← 13 bài test tự động (v2.0)
│
├── crypto_engine/            ← 🔐 LÕI MẬT MÃ (4 module)
│   ├── __init__.py
│   ├── key_manager.py        ← Tạo/lưu/load cặp khóa RSA & ECDSA
│   ├── hasher.py             ← Băm SHA-256 ở mức nhị phân
│   ├── signer.py             ← Ký số + đóng gói .sigbundle
│   └── verifier.py           ← Xác minh chữ ký + phát hiện giả mạo
│
├── templates/                ← 🖥️ GIAO DIỆN WEB
│   ├── base.html             ← Template gốc (nav, footer)
│   ├── index.html            ← Trang chủ
│   ├── sender.html           ← Giao diện Sender
│   ├── receiver.html         ← Giao diện Receiver
│   └── demo.html             ← Giao diện Demo tấn công
│
├── static/                   ← 🎨 STYLE & SCRIPT
│   ├── css/style.css         ← Giao diện dark mode
│   └── js/app.js             ← Logic frontend (upload, gọi API, hiển thị)
│
├── keys/                     ← Lưu cặp khóa đã tạo (.pem)
├── signed_files/             ← Lưu file .sigbundle đã ký
└── uploads/                  ← File PDF/bundle được upload
```

---

## 2. Kiến thức nền tảng cần nắm

### 2.1. Mật mã bất đối xứng (Asymmetric Cryptography)

Mỗi người dùng có **2 khóa**:

```
┌─────────────────────────────────────────────────┐
│  Private Key (Khóa bí mật)                      │
│  - CHỈ người sở hữu biết                        │
│  - Dùng để KÝ (sign)                            │
│  - KHÔNG BAO GIỜ chia sẻ                        │
├─────────────────────────────────────────────────┤
│  Public Key (Khóa công khai)                     │
│  - Ai cũng có thể biết                          │
│  - Dùng để XÁC MINH (verify)                    │
│  - Phân phối tự do                              │
└─────────────────────────────────────────────────┘
```

**Quan hệ toán học:**
- **RSA**: Dựa trên bài toán phân tích thừa số nguyên tố
  - Chọn 2 số nguyên tố lớn `p`, `q` → `n = p × q`
  - `e` (public exponent) = 65537 (chuẩn)
  - `d` (private exponent) thỏa: `e × d ≡ 1 (mod φ(n))`
  - Public key = `(n, e)`, Private key = `(n, d)`
  
- **ECDSA**: Dựa trên đường cong Elliptic
  - Chọn điểm sinh `G` trên đường cong
  - Private key `d` = số nguyên ngẫu nhiên
  - Public key `Q = d × G` (nhân vô hướng trên đường cong)
  - Bài toán ngược (tìm `d` từ `Q` và `G`) là **cực kỳ khó** → ECDLP

### 2.2. Hàm băm SHA-256 (Hash Function)

```
Input (bất kỳ kích thước)  →  SHA-256  →  Output (luôn 256 bit = 64 ký tự hex)
```

**3 tính chất quan trọng:**

| Tính chất | Ý nghĩa | Ví dụ trong dự án |
|-----------|---------|-------------------|
| **Deterministic** (Tất định) | Cùng input → cùng output | Sender và Receiver băm cùng file → cùng hash |
| **Collision Resistant** (Kháng va chạm) | Không thể tìm 2 input khác nhau có cùng hash | Attacker không thể tạo file giả có cùng hash |
| **Avalanche Effect** (Hiệu ứng tuyết lở) | Thay đổi 1 bit input → ~50% output thay đổi | Đổi 1 byte → 93.8% ký tự hash bị đổi! |

### 2.3. Chữ ký số (Digital Signature)

```
KÝ:     Hash(file) + Private Key  → Signature
XÁC MINH: Hash(file) + Public Key + Signature → ✓ hoặc ✗
```

**Non-repudiation (Không thể chối bỏ):**
- Vì chỉ người có Private Key mới tạo được chữ ký hợp lệ
- Nên người ký **không thể phủ nhận** việc mình đã ký
- Bất kỳ ai có Public Key đều xác minh được → không cần sự hợp tác của người ký

### 2.4. PKI (Public Key Infrastructure)

> **Quan trọng cho thuyết trình:** Trong dự án này, chúng ta đóng gói Public Key chung trong `.sigbundle` vì đây là **demo local**. Trong thực tế, Public Key được phân phối qua:
> - **Certificate Authority (CA)**: Tổ chức uy tín cấp chứng chỉ số (VD: Let's Encrypt, DigiCert)
> - **PKI Infrastructure**: Hạ tầng khóa công khai với chuỗi chứng chỉ (chain of trust)

---

## 3. Kiến trúc hệ thống

### Sơ đồ tổng quan

```
┌──────────────┐     .sigbundle      ┌──────────────┐
│   SENDER     │ ──────────────────→ │   RECEIVER   │
│              │   (qua kênh không   │              │
│ 1. Chọn PDF  │    tin cậy)         │ 1. Nhận bundle│
│ 2. Băm SHA256│                     │ 2. Tách các   │
│ 3. Ký bằng   │                     │    thành phần │
│    Private   │                     │ 3. Băm lại PDF│
│    Key       │                     │ 4. So sánh    │
│ 4. Đóng gói  │                     │    chữ ký     │
│    bundle    │                     │ 5. ✓ hoặc ✗   │
└──────────────┘                     └──────────────┘
                        ↑
                        │ (có thể bị chặn/sửa)
                 ┌──────────────┐
                 │   ATTACKER   │
                 │              │
                 │ Sửa 1 byte   │
                 │ hoặc thay    │
                 │ file giả     │
                 └──────────────┘
```

### Định dạng `.sigbundle`

File `.sigbundle` thực chất là một **file ZIP** chứa 4 thành phần:

```
file_signed.sigbundle (ZIP)
├── document.pdf      ← File PDF gốc (raw bytes)
├── signature.bin     ← Chữ ký số (dạng binary)
├── public_key.pem    ← Public key của người ký (dạng PEM)
└── manifest.json     ← Metadata (thuật toán, hash, thời gian, ghi chú PKI)
```

**Ví dụ manifest.json (v2.0):**
```json
{
  "version": "2.0",
  "algorithm": "RSA-PSS",
  "hash_algorithm": "SHA-256",
  "file_hash": "9eb635da5a370734a6f45c52fbd5598439ee64e9...",
  "tbs_hash": "0192beffdb602f6711b3c7b88893a3b895eebc1e...",
  "metadata_signed": true,
  "file_name": "contract.pdf",
  "file_size": 594,
  "key_size": 2048,
  "signed_at": "2026-04-15T03:33:22+00:00",
  "pki_notice": "...",
  "tbs_notice": "The digital signature covers BOTH the file content AND metadata..."
}
```

> 🔗 **v2.0 — Metadata Binding:** Trường `metadata_signed: true` cho biết chữ ký bao phủ cả file content LẪN metadata (timestamp, algorithm). Nếu attacker sửa bất kỳ trường nào trong manifest → chữ ký sẽ invalid.

---

## 4. Chi tiết từng Module

### 4.1. `key_manager.py` — Quản lý khóa

**Mục đích:** Tạo, lưu trữ, đọc và quản lý cặp khóa RSA/ECDSA.

#### Hàm `generate_rsa_keypair(key_size, key_name, password)`

```python
# Bước 1: Tạo Private Key RSA
private_key = rsa.generate_private_key(
    public_exponent=65537,   # Số mũ công khai chuẩn (luôn dùng 65537)
    key_size=key_size,       # 2048 hoặc 4096 bits
)
```

**Giải thích từng tham số:**
- `public_exponent=65537`: Đây là giá trị `e` trong RSA. Số 65537 (= 2^16 + 1) được chọn vì:
  - Là số nguyên tố → đảm bảo tồn tại `d` nghịch đảo
  - Dạng nhị phân chỉ có 2 bit 1 → phép lũy thừa nhanh
  - Đủ lớn để an toàn, đủ nhỏ để hiệu quả
- `key_size=2048`: Độ dài khóa. 2048 bits = an toàn đến ~2030. 4096 bits = an toàn hơn nhưng chậm hơn.

```python
# Bước 2: Trích xuất Public Key từ Private Key
public_key = private_key.public_key()
# Quan hệ: Public Key được TÍNH từ Private Key (không phải ngược lại)
```

```python
# Bước 3: Lưu Private Key dạng PEM (PKCS8)
private_pem = private_key.private_bytes(
    encoding=Encoding.PEM,              # Dạng text, bắt đầu bằng "-----BEGIN PRIVATE KEY-----"
    format=PrivateFormat.PKCS8,         # Chuẩn định dạng PKCS#8
    encryption_algorithm=NoEncryption() # Hoặc BestAvailableEncryption(password)
)
```

```python
# Bước 4: Lưu Public Key dạng PEM
public_pem = public_key.public_bytes(
    encoding=Encoding.PEM,
    format=PublicFormat.SubjectPublicKeyInfo  # Chuẩn X.509
)
```

```python
# Bước 5: Tạo fingerprint (vân tay khóa) = SHA-256 của Public Key
digest = hashlib.sha256(public_pem_bytes).hexdigest()
# VD: "7c:bc:19:30:9f:9a:3a:df:28:b7:49:ca:d2:0d:8b:af"
# Fingerprint giúp nhận diện nhanh khóa mà không cần so sánh toàn bộ PEM
```

**Tại sao cần fingerprint?**
- Public Key rất dài (hàng trăm ký tự PEM)
- Fingerprint chỉ 32 ký tự → dễ đọc, dễ so sánh
- Giống như "số CMND" của một public key

#### Hàm `generate_ecdsa_keypair(curve_name, key_name, password)`

Logic tương tự RSA nhưng dùng đường cong Elliptic:

```python
# Các đường cong được hỗ trợ
curves = {
    "secp256r1": ec.SECP256R1(),  # P-256, 128-bit security, NIST recommend
    "secp384r1": ec.SECP384R1(),  # P-384, 192-bit security
    "secp521r1": ec.SECP521R1(),  # P-521, 256-bit security
}

# Tạo private key trên đường cong đã chọn
private_key = ec.generate_private_key(curve)
# Nội bộ: chọn số nguyên ngẫu nhiên d ∈ [1, n-1]
# Tính Q = d × G (nhân vô hướng điểm G trên đường cong)
```

**So sánh RSA vs ECDSA:**

| Tiêu chí | RSA-2048 | ECDSA P-256 |
|----------|----------|-------------|
| Độ an toàn | 112 bits | 128 bits |
| Kích thước khóa | 2048 bits | 256 bits |
| Tốc độ ký | Chậm hơn | **Nhanh hơn** |
| Tốc độ xác minh | **Nhanh hơn** | Chậm hơn |
| Kích thước chữ ký | 256 bytes | 64 bytes |

#### Các hàm phụ trợ

```python
load_private_key(key_name, password)    # Đọc private key từ file PEM
load_public_key(key_name)               # Đọc public key từ file PEM
load_public_key_from_pem(pem_bytes)     # Đọc public key từ bytes PEM (dùng khi verify bundle)
get_public_key_pem(key_name)            # Lấy raw PEM bytes (dùng khi đóng gói bundle)
list_keys()                             # Liệt kê tất cả cặp khóa (đọc *_meta.json)
delete_key(key_name)                    # Xóa cặp khóa (3 files: private, public, meta)
```

**Mỗi cặp khóa tạo ra 3 file:**
```
keys/
├── test_rsa_2048_private.pem    ← Private key (GIỮ BÍ MẬT)
├── test_rsa_2048_public.pem     ← Public key (chia sẻ tự do)
└── test_rsa_2048_meta.json      ← Metadata (algorithm, fingerprint, timestamp)
```

---

### 4.2. `hasher.py` — Băm SHA-256

**Mục đích:** Tính hash SHA-256 của file ở mức **nhị phân thuần túy** (raw bytes).

#### THIẾT KẾ QUAN TRỌNG: Binary-level Hashing

```python
# Module này KHÔNG BAO GIỜ parse/render/hiểu nội dung file
# Nó đọc RAW BYTES → đảm bảo:
# 1. Sender và Receiver băm cùng bytes → cùng hash
# 2. File bị hỏng (không mở được bằng PDF viewer) vẫn được băm
# 3. Tính toàn vẹn ở mức NHỊ PHÂN, không phải mức nội dung
```

#### Hàm `hash_file(file_path)`

```python
def hash_file(file_path):
    sha256 = hashlib.sha256()           # Khởi tạo bộ băm SHA-256
    
    with open(file_path, "rb") as f:    # "rb" = read binary (quan trọng!)
        while True:
            chunk = f.read(65536)       # Đọc từng khối 64KB
            if not chunk:               # Hết file → dừng
                break
            sha256.update(chunk)        # Cập nhật hash với khối mới
    
    return sha256.hexdigest()           # Trả về chuỗi hex 64 ký tự
```

**Tại sao đọc theo chunk (khối)?**
- File PDF có thể rất lớn (hàng trăm MB)
- Nếu `f.read()` đọc hết → tốn RAM
- Đọc từng khối 64KB → tiết kiệm bộ nhớ, hash vẫn đúng
- `sha256.update()` cho phép cập nhật dần dần (streaming)

#### Hàm `hash_bytes(data)`

```python
def hash_bytes(data):
    return hashlib.sha256(data).hexdigest()
# Dùng khi đã có bytes trong RAM (VD: đọc từ ZIP bundle)
```

#### Hàm `compare_hashes(hash1, hash2)` — So sánh ký tự

```python
def compare_hashes(hash1, hash2):
    diff_positions = []
    for i in range(max(len(hash1), len(hash2))):
        if hash1[i] != hash2[i]:
            diff_positions.append(i)    # Ghi nhận vị trí khác biệt
    
    return {
        "match": hash1 == hash2,        # True/False
        "diff_positions": [3, 5, 7...], # Danh sách vị trí khác
        "diff_count": 60,               # Số ký tự khác
        "total_chars": 64,              # Tổng ký tự (SHA-256 = 64 hex chars)
    }
```

**Mục đích:** Phục vụ hiển thị **hash diff trực quan** trên giao diện — mỗi ký tự hex được tô màu:
- 🟢 Xanh = giống nhau
- 🔴 Đỏ (nhấp nháy) = khác nhau

Đây chính là bằng chứng trực quan của **Avalanche Effect**.

---

### 4.3. `signer.py` — Ký số

**Mục đích:** Ký file PDF bằng Private Key và đóng gói thành `.sigbundle`.

#### Hàm `sign_file(file_path, key_name, password)`

**Quy trình 8 bước (v2.0):**

```
Bước 1: Đọc file PDF → raw bytes
Bước 2: Tính SHA-256 hash (cho hiển thị)
Bước 3: Load Private Key từ file PEM
Bước 4: Xác định algorithm, tạo timestamp
Bước 5: Xây dựng TBS blob = file_bytes + timestamp + algorithm  ← MỚI v2.0
Bước 6: Ký TBS blob (KHÔNG CHỈ file data)
Bước 7: Tạo manifest.json (metadata)
Bước 8: Đóng gói ZIP → .sigbundle
```

**Bước 5 — TBS (To-Be-Signed) Blob (MỚI v2.0):**

```python
def build_tbs_data(file_data, signed_at, algorithm):
    separator = b"||METADATA||"
    field_sep = b"||"
    return file_data + separator + signed_at.encode() + field_sep + algorithm.encode()

# VD: tbs_data = [PDF bytes] + b"||METADATA||" + b"2026-05-05T06:18:14" + b"||" + b"RSA-PSS"
# → Chữ ký bao phủ CẢ nội dung file LẪN thời gian ký + thuật toán
# → Attacker không thể sửa timestamp mà không làm hỏng chữ ký!
```

**Bước 6 chi tiết — Ký RSA-PSS (v2.0 ký TBS blob):**

```python
if isinstance(private_key, RSAPrivateKey):
    signature = private_key.sign(
        tbs_data,                           # v2.0: TBS blob (file + metadata), không chỉ file_data
        padding.PSS(                        # Padding scheme: PSS (Probabilistic)
            mgf=padding.MGF1(hashes.SHA256()),  # Mask Generation Function
            salt_length=padding.PSS.MAX_LENGTH  # Salt ngẫu nhiên → mỗi lần ký ra chữ ký khác
        ),
        hashes.SHA256()                     # Hash algorithm
    )
```

**Tại sao dùng RSA-PSS (không dùng PKCS#1 v1.5)?**
- PSS = **Probabilistic** Signature Scheme → có salt ngẫu nhiên
- Cùng file, cùng key, ký 2 lần → 2 chữ ký **KHÁC NHAU** (nhưng cả 2 đều valid)
- An toàn hơn PKCS#1 v1.5 vì kháng các tấn công kiểu Bleichenbacher

**Bước 4 chi tiết — Ký ECDSA:**

```python
elif isinstance(private_key, EllipticCurvePrivateKey):
    signature = private_key.sign(
        file_data,                      # Dữ liệu cần ký
        ec.ECDSA(hashes.SHA256())       # ECDSA với SHA-256
    )
```

**Bước 6 — Đóng gói .sigbundle:**

```python
with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_DEFLATED) as zf:
    zf.writestr("document.pdf", file_data)          # PDF gốc
    zf.writestr("signature.bin", signature)          # Chữ ký
    zf.writestr("public_key.pem", public_key_pem)    # Public key
    zf.writestr("manifest.json", json.dumps(manifest))  # Metadata
```

> ⚠️ **Ghi chú PKI:** Public key được đóng gói chung trong bundle chỉ để phục vụ demo local. Trong thực tế, public key sẽ được phân phối qua PKI/CA. Điều này được ghi rõ trong `manifest.json → pki_notice`.

---

### 4.4. `verifier.py` — Xác minh chữ ký

**Mục đích:** Xác minh tính toàn vẹn của file và tính hợp lệ của chữ ký.

#### Hàm `verify_bundle(bundle_path)`

**Quy trình 5 bước:**

```
Bước 1: Giải nén .sigbundle → lấy PDF, signature, public key, manifest
Bước 2: Băm lại PDF bằng SHA-256 (RAW BYTES, không parse PDF)
Bước 3: So sánh hash gốc (trong manifest) với hash tính lại
Bước 4: Xác minh chữ ký bằng Public Key
Bước 5: Trả về kết quả chi tiết
```

**Bước 2 — Binary-level Integrity (ĐIỂM CỘNG LỚN):**

```python
# QUAN TRỌNG: hash RAW BYTES, KHÔNG parse PDF
recomputed_hash = hash_bytes(file_data)
# → file_data là bytes thô từ ZIP
# → Không cần biết file có phải PDF hợp lệ hay không
# → Ngay cả file bị hỏng hoàn toàn vẫn được băm → vẫn phát hiện giả mạo
```

**Điều này chứng minh:**
- Tính toàn vẹn ở mức **nhị phân** (binary level), không phải mức nội dung
- Dù file không mở được bằng PDF viewer → hệ thống vẫn hoạt động
- Bất kỳ thay đổi nào ở mức byte → đều bị phát hiện

**Bước 4 — Xác minh chữ ký RSA-PSS:**

```python
if isinstance(public_key, RSAPublicKey):
    public_key.verify(
        signature,          # Chữ ký cần kiểm tra
        file_data,          # Dữ liệu gốc (raw bytes)
        padding.PSS(        # Cùng padding scheme như lúc ký
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    # Nếu không raise exception → chữ ký HỢP LỆ
    signature_valid = True
```

**Cơ chế verify hoạt động thế nào (RSA)?**
```
1. Dùng Public Key giải mã signature → lấy ra hash_from_signature
2. Tính hash_from_file = SHA-256(file_data)
3. So sánh hash_from_signature == hash_from_file
4. Nếu khớp → ✓ Valid | Nếu không khớp → ✗ Invalid (raise InvalidSignature)
```

**Xử lý lỗi:**

```python
except InvalidSignature:
    # Chữ ký KHÔNG HỢP LỆ → file đã bị sửa đổi!
    signature_valid = False
    verification_error = "Digital signature verification FAILED - file integrity compromised!"
```

#### Hàm `tamper_bundle(bundle_path, tamper_type)` — Mô phỏng tấn công

**Loại 1: `modify_byte` — Sửa 1 byte**

```python
# Tìm vị trí ở giữa file
tamper_pos = len(file_data) // 2

# Lật bit thấp nhất (LSB flip) bằng XOR
original_byte = file_data[tamper_pos]         # VD: 0x54 = 01010100
tampered_byte = original_byte ^ 0x01          # VD: 0x55 = 01010101
file_data[tamper_pos] = tampered_byte         # Chỉ đổi 1 bit!

# Giữ nguyên signature gốc → đóng gói lại
# → Khi verify: hash mới ≠ hash gốc → InvalidSignature
```

**Kết quả thực tế từ test:**
```
Original: 9eb635da5a370734a6f45c52fbd5598439ee64e9e28df73e5b5ce58591500951
Tampered: 23a6e631cbe2da16e76be65827aaaa9e4b7ed0abad6a4b7707195cd49ec95095
                                                    
→ 60/64 ký tự khác nhau = 93.8% → Avalanche Effect!
```

**Loại 2: `signature_reuse` — Tái sử dụng chữ ký**

```python
# Thay toàn bộ nội dung PDF bằng file giả
fake_content = b"%PDF-1.4\nThis is a FAKE document...\n%%EOF\n"
file_data = bytearray(fake_content)

# Giữ nguyên signature của file GỐC → đóng gói lại
# → Khi verify: hash(fake) ≠ hash(original) → InvalidSignature
```

**Loại 3: `tamper_metadata` — Giả mạo metadata (MỚI v2.0)**

```python
# Giữ nguyên file PDF và chữ ký, CHỈ sửa timestamp
original_time = manifest["signed_at"]   # "2026-05-05T06:18:14"
manifest["signed_at"] = "2020-01-01T00:00:00+00:00"  # Giả mạo!

# Đóng gói lại → Khi verify:
# TBS mới = file + "2020-01-01..." + algorithm  ≠  TBS gốc
# → InvalidSignature! Phát hiện giả mạo metadata!
```

**Tại sao cần v2.0?** Trong v1.0, chữ ký chỉ bao phủ file content. Attacker có thể sửa `signed_at` trong manifest mà chữ ký vẫn valid! v2.0 khắc phục bằng cách ký cả metadata.

**Mục đích demo:** Chứng minh chữ ký số **gắn chặt** với cả nội dung file LẪN metadata. Không thể sửa bất kỳ trường nào.

---

## 5. Luồng hoạt động (Workflow)

### 5.1. Luồng Ký (Sender Flow)

```
Người dùng                    Hệ thống
    │                             │
    │── Chọn thuật toán ─────────→│
    │   (RSA 2048 / ECDSA P-256)  │
    │                             │── Tạo cặp khóa (private + public)
    │                             │── Lưu vào keys/*.pem
    │←─ Hiển thị fingerprint ────│
    │                             │
    │── Upload file PDF ─────────→│
    │── Chọn key đã tạo ────────→│
    │── Nhấn "Sign Document" ───→│
    │                             │── Đọc PDF → raw bytes
    │                             │── Tính SHA-256(raw bytes)
    │                             │── Load private key
    │                             │── Ký: sign(data, private_key)
    │                             │── Đóng gói .sigbundle (ZIP)
    │                             │
    │←─ Hiển thị kết quả ────────│
    │   (hash, algorithm, sig)    │
    │←─ Link download bundle ────│
    │                             │
    ▼                             ▼
```

### 5.2. Luồng Xác minh (Receiver Flow)

```
Người dùng                    Hệ thống
    │                             │
    │── Upload .sigbundle ───────→│
    │── Nhấn "Verify" ──────────→│
    │                             │── Giải nén ZIP
    │                             │── Lấy: PDF, signature, public key, manifest
    │                             │── Tính SHA-256(PDF raw bytes)
    │                             │── So sánh hash mới vs hash trong manifest
    │                             │── Verify: verify(sig, data, public_key)
    │                             │
    │                             │── Nếu ĐÚNG:
    │←─ ✓ "Signature Valid" ─────│   (SweetAlert2 xanh)
    │                             │
    │                             │── Nếu SAI:
    │←─ ✗ "SIGNATURE INVALID" ──│   (SweetAlert2 đỏ, nhấp nháy)
    │←─ Hiển thị hash diff ──────│   (từng ký tự xanh/đỏ)
    │                             │
    ▼                             ▼
```

### 5.3. Luồng Demo Tấn công (Attack Flow)

```
Người dùng                    Hệ thống
    │                             │
    │── Upload .sigbundle ───────→│
    │── Chọn loại tấn công ─────→│
    │   ☐ Single Byte Mod         │
    │   ☐ Signature Reuse         │
    │   ☐ Metadata Tampering ←NEW │
    │── Nhấn "Execute Attack" ──→│
    │                             │
    │                             │── Bước 1: Verify bundle GỐC → ✓ Valid
    │                             │── Bước 2: Thực hiện tấn công
    │                             │   - modify_byte: đổi 1 byte (XOR 0x01)
    │                             │   - signature_reuse: thay nội dung, giữ sig
    │                             │── Bước 3: Đóng gói lại (giữ sig gốc)
    │                             │── Bước 4: Verify bundle ĐÃ SỬA → ✗ Invalid
    │                             │
    │←─ Hiển thị so sánh ────────│
    │   ┌─────────┬─────────┐    │
    │   │ Original│ Tampered│    │
    │   │ ✓ Valid │ ✗ INVALID│   │
    │   └─────────┴─────────┘    │
    │                             │
    │←─ Hash Diff Grid ──────────│
    │   Từng ký tự: 🟢🔴🔴🟢🔴   │
    │   "60/64 ký tự khác (93.8%)"│
    │                             │
    ▼                             ▼
```

---

## 6. Flask Backend — Giải thích từng Route

### File `app.py`

```python
app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(32).hex()       # Khóa bí mật cho session
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024   # Giới hạn upload 50MB
```

### Bảng các Route

| Route | Method | Hàm | Chức năng |
|-------|--------|-----|-----------|
| `/` | GET | `index()` | Trang chủ — giới thiệu dự án |
| `/sender` | GET | `sender()` | Giao diện ký — load danh sách key |
| `/sender/generate-keys` | POST | `api_generate_keys()` | API tạo cặp khóa mới |
| `/sender/sign` | POST | `api_sign_file()` | API ký file PDF |
| `/sender/download/<name>` | GET | `download_bundle()` | Tải .sigbundle |
| `/receiver` | GET | `receiver()` | Giao diện xác minh |
| `/receiver/verify` | POST | `api_verify_bundle()` | API xác minh bundle |
| `/receiver/report` | POST | `api_download_report()` | Tải báo cáo xác minh (Audit Report) |
| `/demo` | GET | `demo()` | Giao diện demo tấn công |
| `/demo/tamper` | POST | `api_tamper_bundle()` | API mô phỏng tấn công (3 loại) |
| `/api/keys` | GET | `api_list_keys()` | Liệt kê cặp khóa |
| `/api/keys/<name>` | DELETE | `api_delete_key()` | Xóa cặp khóa |

### Chi tiết Route quan trọng

#### `POST /sender/sign` — Ký file

```python
def api_sign_file():
    # 1. Lấy file PDF từ request
    file = request.files["file"]
    key_name = request.form.get("key_name")
    
    # 2. Lưu file vào thư mục uploads/
    filename = secure_filename(file.filename)   # Làm sạch tên file (bảo mật)
    file.save(os.path.join(UPLOAD_DIR, filename))
    
    # 3. Gọi crypto_engine.signer.sign_file()
    result = sign_file(file_path, key_name)
    
    # 4. Trả JSON kết quả cho frontend
    return jsonify(result)   # {success, file_hash, algorithm, bundle_name, ...}
```

#### `POST /receiver/verify` — Xác minh

```python
def api_verify_bundle():
    # 1. Lấy file .sigbundle từ request
    bundle = request.files["bundle"]
    bundle.save(os.path.join(UPLOAD_DIR, filename))
    
    # 2. Gọi crypto_engine.verifier.verify_bundle()
    result = verify_bundle(bundle_path)
    
    # 3. Trả JSON kết quả
    return jsonify(result)   # {signature_valid, hash_match, original_hash, recomputed_hash, ...}
```

#### `POST /demo/tamper` — Demo tấn công

```python
def api_tamper_bundle():
    # 1. Verify bundle GỐC trước (phải valid)
    original_result = verify_bundle(bundle_path)
    
    # 2. Tamper và verify lại (phải invalid)
    tamper_result = tamper_bundle(bundle_path, tamper_type=tamper_type)
    
    # 3. Trả CẢ HAI kết quả để so sánh
    return jsonify({
        "original_verification": original_result,   # ✓ Valid
        "tamper_result": tamper_result,               # ✗ Invalid + chi tiết
    })
```

---

## 7. Frontend — Giao diện người dùng

### 7.1. `app.js` — Các hàm JavaScript chính

| Hàm | Chức năng |
|-----|-----------|
| `handleDragOver/Drop()` | Xử lý kéo thả file |
| `handleFileSelect()` | Xử lý chọn file, hiện preview |
| `generateKeys()` | Gọi API tạo khóa → SweetAlert2 thông báo |
| `signFile()` | Upload PDF + gọi API ký → hiện kết quả |
| `verifyBundle()` | Upload bundle + gọi API verify → hiện ✓ hoặc ✗ |
| `runAttack()` | Upload bundle + chọn loại tấn công → hiện so sánh |
| `showVerificationResult()` | Hiển thị kết quả verify + hash diff |
| `downloadAuditReport()` | Tải báo cáo xác minh (Audit Report) |
| `buildHashDiffGrid()` | Vẽ lưới so sánh hash từng ký tự |
| `renderHashChars()` | Tô màu từng ký tự hash (xanh/đỏ) |

### 7.2. SweetAlert2 — Thông báo đẹp

```javascript
// Khi verify THÀNH CÔNG:
Swal.fire({
    icon: 'success',
    title: '✓ Signature Valid',
    text: 'The file has not been modified since it was signed.',
    background: '#111827',    // Dark theme
    confirmButtonColor: '#10b981',  // Xanh lá
});

// Khi verify THẤT BẠI (bị giả mạo):
Swal.fire({
    icon: 'error',
    title: '✗ SIGNATURE INVALID',
    html: '<p style="color:#ef4444;">The file has been tampered with!</p>',
    background: '#111827',
    confirmButtonColor: '#ef4444',  // Đỏ
});
```

### 7.3. Hash Diff Grid — So sánh trực quan

```javascript
function buildHashDiffGrid(hash1, hash2) {
    // So sánh từng ký tự
    for (let i = 0; i < hash1.length; i++) {
        if (hash1[i] !== hash2[i]) {
            // Ký tự KHÁC → class "hash-char-diff" (đỏ, nhấp nháy)
            diffs.add(i);
        }
        // Ký tự GIỐNG → class "hash-char-match" (xanh lá)
    }
    // Hiển thị: "60/64 characters differ (93.8%) — SHA-256 Avalanche Effect"
}
```

**CSS animation cho ký tự khác biệt:**
```css
.hash-char-diff {
    background: rgba(239, 68, 68, 0.2);   /* Nền đỏ nhạt */
    color: #ef4444;                         /* Chữ đỏ */
    border: 1px solid rgba(239, 68, 68, 0.4);
    animation: pulse-char 1.5s infinite;    /* Nhấp nháy liên tục */
}
```

---

## 8. Các kịch bản Demo quan trọng

### Kịch bản 1: Ký và xác minh thành công ✓

```
1. Mở http://127.0.0.1:5000/sender
2. Nhấn "Generate" → tạo RSA 2048-bit key
3. Upload file PDF bất kỳ
4. Nhấn "Sign Document" → download .sigbundle
5. Mở http://127.0.0.1:5000/receiver
6. Upload file .sigbundle vừa tải
7. Nhấn "Verify Signature"
8. KẾT QUẢ: ✓ Signature Valid (banner xanh)
```

### Kịch bản 2: Phát hiện sửa 1 byte ✗

```
1. Mở http://127.0.0.1:5000/demo
2. Upload file .sigbundle hợp lệ
3. Chọn "Single Byte Modification"
4. Nhấn "Execute Attack & Verify"
5. KẾT QUẢ:
   - Bên trái: ✓ Original Valid
   - Bên phải: ✗ Tampered INVALID
   - Hash Diff: 60/64 ký tự khác (93.8%) ← AVALANCHE EFFECT
```

### Kịch bản 3: Tái sử dụng chữ ký thất bại ✗

```
1. Mở http://127.0.0.1:5000/demo
2. Upload file .sigbundle hợp lệ
3. Chọn "Signature Reuse Attack"
4. Nhấn "Execute Attack & Verify"
5. KẾT QUẢ:
   - ✗ INVALID — chữ ký gắn chặt với nội dung, không thể tái sử dụng
   - Hash hoàn toàn khác → chứng minh signature là content-bound
```

### Kịch bản 4: File bị hỏng vẫn phát hiện (Binary-level)

```
1. Sửa file PDF trong bundle đến mức không mở được bằng PDF viewer
2. Verify → vẫn hiện ✗ INVALID với hash mismatch
3. CHỨNG MINH: Hệ thống kiểm tra ở mức nhị phân, không cần parse PDF
```

### Kịch bản 5: Giả mạo metadata bị phát hiện (v2.0) 🆕

```
1. Mở http://127.0.0.1:5000/demo
2. Upload file .sigbundle hợp lệ
3. Chọn "Metadata Tampering (Timestamp Forgery)"
4. Nhấn "Execute Attack & Verify"
5. KẾT QUẢ:
   - File content KHÔNG THAY ĐỔI
   - Chỉ sửa timestamp: "2026-05-05" → "2020-01-01"
   - ✗ INVALID! Chữ ký bao phủ cả metadata → phát hiện!
```

### Kịch bản 6: Tải Audit Report 🆕

```
1. Mở http://127.0.0.1:5000/receiver
2. Upload .sigbundle → Verify
3. Sau khi thấy kết quả → nhấn "Download Verification Report"
4. File .txt được tải về chứa: thời gian, hash, fingerprint, kết luận
5. Dùng làm bằng chứng kiểm toán (audit trail)
```

---

## 9. Câu hỏi thường gặp khi thuyết trình

### Q1: "Tại sao dùng RSA-PSS thay vì PKCS#1 v1.5?"
**A:** RSA-PSS có salt ngẫu nhiên, mỗi lần ký tạo chữ ký khác nhau (probabilistic). PKCS#1 v1.5 là deterministic — cùng input luôn ra cùng output, dễ bị tấn công kiểu Bleichenbacher. PSS được khuyến nghị bởi NIST và các tiêu chuẩn hiện đại.

### Q2: "Tại sao đóng gói Public Key trong bundle? Điều này có an toàn không?"
**A:** Trong demo local, chúng tôi đóng gói chung cho tiện. Trong thực tế, đây là **không an toàn** vì attacker có thể thay public key giả. Public key nên được phân phối qua **PKI/CA** (Certificate Authority) với chứng chỉ số để đảm bảo tính xác thực.

### Q3: "Hiệu ứng tuyết lở (Avalanche Effect) là gì?"
**A:** Khi thay đổi dù chỉ 1 bit trong input, khoảng 50% bits trong output hash sẽ thay đổi. Trong demo: đổi 1 byte (8 bits) → 93.8% ký tự hash hex thay đổi (60/64). Điều này làm cho attacker không thể dự đoán hash mới.

### Q4: "Non-repudiation hoạt động thế nào?"
**A:** Vì chỉ người sở hữu Private Key mới tạo được chữ ký hợp lệ, và bất kỳ ai có Public Key đều verify được → người ký không thể phủ nhận. Đây là nền tảng pháp lý của chữ ký số.

### Q5: "Tại sao hệ thống vẫn hoạt động với file PDF bị hỏng?"
**A:** Vì module `hasher.py` đọc **raw bytes** (chế độ `"rb"`) mà không parse PDF. Hash được tính trên dãy byte thô → không cần file phải là PDF hợp lệ. Đây là **tính toàn vẹn mức nhị phân** (binary-level integrity).

### Q6: "Signature reuse attack chứng minh điều gì?"
**A:** Chứng minh chữ ký số **gắn chặt với nội dung file** (content-bound). Không thể tách chữ ký từ file A rồi gán cho file B. Vì hash(A) ≠ hash(B), nên verify(sig_A, B) sẽ fail.

### Q7: "RSA và ECDSA khác nhau thế nào?"
**A:** 
- RSA dựa trên bài toán phân tích thừa số → khóa lớn (2048+ bits)
- ECDSA dựa trên đường cong Elliptic → khóa nhỏ hơn (256 bits) nhưng an toàn tương đương
- ECDSA nhanh hơn khi ký, RSA nhanh hơn khi verify
- Cả hai đều an toàn nếu dùng đúng kích thước khóa

### Q8: "Hàm băm SHA-256 có vai trò gì trong ký số?"
**A:** 3 vai trò chính:
1. **Nén dữ liệu**: File bất kỳ kích thước → hash 256 bit. Ký hash nhanh hơn ký toàn bộ file.
2. **Phát hiện thay đổi**: Đổi 1 bit → hash hoàn toàn khác (avalanche effect).
3. **Liên kết nội dung với chữ ký**: Signature(hash) gắn chặt chữ ký với nội dung cụ thể.

### Q9: "Tại sao v2.0 cần ký cả metadata?" 🆕
**A:** Trong v1.0, chữ ký chỉ bảo vệ nội dung file. Attacker có thể giải nén bundle, sửa `signed_at` (thời gian ký) thành ngày khác, nén lại → chữ ký vẫn valid! v2.0 khắc phục bằng cách tạo TBS blob = `file_bytes + timestamp + algorithm`, ký TBS thay vì chỉ file → sửa bất kỳ trường nào cũng phá hỏng chữ ký.

### Q10: "Audit Report dùng để làm gì?" 🆕
**A:** Trong hệ thống doanh nghiệp, mỗi lần xác minh chữ ký cần có **bằng chứng kiểm toán** (audit trail). Report chứa: thời gian xác minh, hash gốc vs hash tính lại, fingerprint khóa, và kết luận Valid/Invalid. Đây là yêu cầu tuân thủ (compliance) trong tài chính, y tế, pháp lý.

---

## 10. Cách chạy dự án

### 10.1. Chạy dưới Local (Máy tính cá nhân)

#### Cài đặt
```bash
cd f:\Hoc_tap\BAO MAT MT\digital-signature-tool

# Cài thư viện cần thiết
pip install -r requirements.txt

# Chạy server
python app.py
```

#### Mở trình duyệt
```
http://127.0.0.1:5000         ← Trang chủ
http://127.0.0.1:5000/sender  ← Ký file (cần đăng nhập)
http://127.0.0.1:5000/receiver ← Xác minh (công cộng)
http://127.0.0.1:5000/demo    ← Demo tấn công
```
*Dưới local, hệ thống sử dụng cơ sở dữ liệu mặc định là **SQLite** (`app.db`) tự động sinh trong thư mục dự án.*

---

### 10.2. Deploy trực tuyến trên Cloud (Railway - khuyến nghị)

Dự án hỗ trợ kiến trúc Hybrid nâng cao, tự động chuyển đổi từ SQLite sang PostgreSQL khi phát hiện môi trường Cloud để phục vụ vận hành thực tế (Production).

#### Bước 1: Đẩy mã nguồn lên GitHub
1. Sử dụng Git để đẩy mã nguồn mới nhất lên GitHub (nhánh `main`).
2. Mã nguồn đã được tối ưu hóa sẵn:
   - File `Procfile` chỉ định cho Web server chạy bằng `gunicorn`.
   - File `requirements.txt` loại bỏ các thư viện rác gây lỗi trên Linux (như `metatrader5`).

#### Bước 2: Khởi tạo trên Railway.app
1. Truy cập vào **[Railway.app](https://railway.app/)** và đăng nhập.
2. Bấm **New Project** -> Chọn **Deploy from GitHub repo** -> Chọn Repo của bạn.
3. Khi hệ thống tạo xong Service, bấm **+ New** -> **Database** -> **Add PostgreSQL**.

#### Bước 3: Liên kết Database (PostgreSQL) với Code
1. Nhấp chuột vào ô **PostgreSQL** vừa tạo -> sang tab **Variables** -> Nhấp vào biểu tượng con mắt ở dòng biến `DATABASE_URL` và copy đường link đó.
2. Đóng PostgreSQL, nhấp vào ô **Web Service** (chứa code) -> sang tab **Variables**.
3. Bấm **+ New Variable**, nhập:
   - Name: `DATABASE_URL`
   - Value: *(Dán đường link postgresql://... vừa copy ở trên)*
4. Nhấn **Add**. 

Hệ thống sẽ tự động build lại dựa trên `Procfile` và nhận dạng PostgreSQL. Dữ liệu tài khoản, khóa mật mã và nhật ký audit sẽ được lưu trữ vĩnh viễn trên đám mây.

### Chạy test tự động

```bash
python test_all.py
# → Chạy 13 test cases (v2.0), tất cả phải PASS
```

### Kết quả test (v2.0)

```
TEST 1:  RSA Key Generation                    ✓
TEST 2:  ECDSA Key Generation                  ✓
TEST 3:  Sign PDF (v2.0 metadata bound)        ✓
TEST 4:  Verify valid bundle                   ✓ Signature Valid
TEST 5:  Tamper 1 byte → detect                ✓ 93.8% hash changed!
TEST 6:  Signature reuse attack                ✓ Detected as invalid
TEST 7:  Metadata tampering (timestamp)        ✓ Detected! (v2.0)  🆕
TEST 8:  Sign/verify with ECDSA                ✓
TEST 9:  Wrong key verification                ✓ Rejected
TEST 10: Hash diff visualization               ✓ 60/64 chars differ
TEST 11: Corrupted file integrity              ✓ Binary-level works
TEST 12: Audit report generation (valid)       ✓ 2463 chars  🆕
TEST 13: Audit report generation (invalid)     ✓ Contains WARNING  🆕
═══════════════════════════════════════════════════
ALL 13 TESTS PASSED! (v2.0)
```

---

## Tóm tắt kiến trúc cho Slide thuyết trình

```
┌─────────────────────────────────────────────────────────────┐
│                    DIGITAL SIGNATURE TOOL                     │
├──────────────┬──────────────────────┬───────────────────────┤
│   SENDER     │    CRYPTO ENGINE     │    RECEIVER           │
│              │                      │                       │
│ ┌──────────┐ │ ┌──────────────────┐ │ ┌───────────────────┐ │
│ │ Upload   │ │ │ key_manager.py   │ │ │ Upload .sigbundle │ │
│ │ PDF      │→│ │ - RSA keygen     │ │ │                   │ │
│ │          │ │ │ - ECDSA keygen   │ │ │ Giải nén ZIP      │ │
│ │ Chọn Key │ │ │ - PEM storage    │ │ │                   │ │
│ │          │ │ ├──────────────────┤ │ │ Băm lại SHA-256   │ │
│ │ Sign     │→│ │ hasher.py        │→│ │ (raw bytes)       │ │
│ │          │ │ │ - SHA-256        │ │ │                   │ │
│ │ Download │ │ │ - Binary-level   │ │ │ Verify signature  │ │
│ │ .bundle  │ │ │ - Hash diff      │ │ │ bằng Public Key   │ │
│ └──────────┘ │ ├──────────────────┤ │ │                   │ │
│              │ │ signer.py        │ │ │ ✓ Valid            │ │
│              │ │ - RSA-PSS sign   │ │ │ hoặc              │ │
│              │ │ - ECDSA sign     │ │ │ ✗ INVALID          │ │
│              │ │ - Bundle ZIP     │ │ │ + Hash Diff        │ │
│              │ ├──────────────────┤ │ └───────────────────┘ │
│              │ │ verifier.py      │ │                       │
│              │ │ - Verify sig     │ │                       │
│              │ │ - Tamper detect  │ │                       │
│              │ │ - Reuse detect   │ │                       │
│              │ └──────────────────┘ │                       │
└──────────────┴──────────────────────┴───────────────────────┘
```

---

> **Ghi chú cuối:** File này chứa mọi thứ bạn cần biết để hiểu và thuyết trình dự án. Hãy đọc kỹ phần **"Câu hỏi thường gặp"** (mục 9) vì đây là những câu giáo viên hay hỏi nhất. Chúc bạn thuyết trình thành công! 🎓
