# 📄 README.md — CRUD + XOR Stream Encryption (CLI Version)
# Tugas Kevin Navarro - 230401010033 - Universitas Siber Asia

# 🔐 CRUD dengan Kriptografi Simetris Stream XOR  
Aplikasi ini adalah implementasi **CRUD (Create, Read, Update, Delete)** dengan **kriptografi simetris** menggunakan *stream cipher XOR*.

Data disimpan dalam **CSV terenkripsi** (encrypted database). Sistem dapat:

- Mengambil **plaintext CSV** dan mengonversinya otomatis ke CSV terenkripsi.
- Mengolah **CSV terenkripsi** secara langsung.
- Menyediakan CLI command:
  - `list` — tampilkan seluruh record (dalam bentuk **dekripsi**)
  - `get` — baca 1 record
  - `create`
  - `update`
  - `delete`
  - `dump` — menghasilkan **MySQL dump** (.sql)

Semua enkripsi/ dekripsi menggunakan kunci simetris (`--key <secret>`).

---

# 🚀 Fitur Utama

### ✔ Enkripsi XOR Stream (Simetris, reversible)
- Menggunakan `SHA256(key + nonce + counter)` untuk menghasilkan *keystream*.
- XOR digunakan sebagai operasi enkripsi dan dekripsi.
- Reversible (bolak-balik) selama:
  - kunci sama,
  - nonce sama (nonce = nilai kolom ID),
  - algoritma sama.

### ✔ 2 mode input:
#### **1. Input CSV plaintext → dienkripsi otomatis**
```
python3 crud_xor_csv.py -f input.csv --key "password" list
```
Output encrypted akan dibuat otomatis:
```
input_enc.csv
```

#### **2. Input CSV terenkripsi → digunakan langsung**
```
python3 crud_xor_csv.py -F encrypted.csv --key "password" list
```

### ✔ CRUD Lengkap  
- Create  
- Read (all / by id)  
- Update  
- Delete  

### ✔ Decrypt otomatis saat dibaca  
Data di file tetap **encrypted**, tetapi output CLI selalu **plaintext**.

### ✔ Dump MySQL  
```
python3 crud_xor_csv.py -F data_enc.csv --key "pass" dump --table users --out users.sql
```

---

# 🧩 Struktur Project (Direkomendasikan)

```
📁 project/
│── crud_xor_csv.py         # script utama (CLI)
│── input.csv               # plaintext input (opsional)
│── input_enc.csv           # encrypted storage (dibuat otomatis)
│── dump_encrypted.sql      # hasil MySQL dump
│── README.md               # dokumentasi
│── screenshots/
│     ├── csv_encrypted.png         # screenshot hasil encrypted (Opsional)
│     └── csv_plaintext.png         # screenshot plaintext (opsional)
```

---

# 🛠 Cara Instalasi

Tidak butuh library external. Python bawaan cukup.

```
python3 --version     # disarankan Python 3.8+
```

---

# ⚙ Cara Menggunakan CLI

## 1️⃣ Konversi plaintext CSV menjadi encrypted CSV
```
python3 crud_xor_csv.py -f input.csv --key "mykey" list
```

Ini akan:

- Membuat file baru:  
  **input_enc.csv**
- Menampilkan seluruh data dalam bentuk **plaintext (hasil dekripsi)**

> Kolom pertama CSV harus sebagai **ID**.

---

## 2️⃣ Operasi pada CSV terenkripsi

### List / Read all
```
python3 crud_xor_csv.py -F input_enc.csv --key "mykey" list
```

### Get by ID
```
python3 crud_xor_csv.py -F input_enc.csv --key "mykey" get --id 2
```

### Create row baru
```
python3 crud_xor_csv.py -F input_enc.csv --key "mykey" create --data "id=3,name=Charlie,email=charlie@mail.com,note=new"
```

### Update
```
python3 crud_xor_csv.py -F input_enc.csv --key "mykey" update --id 3 --data "note=updated"
```

### Delete
```
python3 crud_xor_csv.py -F input_enc.csv --key "mykey" delete --id 3
```

---

## 3️⃣ Dump ke MySQL `.sql`

```
python3 crud_xor_csv.py -F input_enc.csv --key "mykey" dump --table users --out users.sql
```

Hasil file berisi:

- CREATE TABLE
- INSERT ciphertext base64

Bisa di-import ke MySQL atau phpMyAdmin.

---

# 🔧 Format CSV Input

CSV **plaintext** (sebelum dienkripsi):

```
id,name,email,note
1,Alice,alice@mail.com,vip
2,Bob,bob@mail.com,regular
```

CSV **encrypted** (hasil sistem):

```
id,name,email,note
1,Qk9FMz...,ASD233...,QWE12...
2,HJKS...,KDJD...,OPO233...
```

Catatan:

- Hanya kolom terenkripsi yang berubah menjadi ciphertext base64.
- Kolom ID disimpan plaintext (untuk nonce).

---

# 🔐 Penjelasan Kriptografi (Singkat)

Digunakan *Stream XOR Cipher*:

```
ciphertext = plaintext XOR keystream
plaintext  = ciphertext XOR keystream
```

Keystream dihasilkan dari:

```
SHA256(key + nonce + counter)
```

Nonce = nilai kolom ID → setiap baris memiliki keystream unik.

Sifat penting:

- **Simetris** → Encrypt & decrypt dengan kunci yang sama.
- **Reversible** → Bisa bolak-balik.
- Keamanan **cukup untuk tugas**, namun **tidak aman untuk produksi**.

---

# 🧪 Contoh Screenshot


### Plaintext CSV
![csv Plaintext screenshot](Tugas-Kripto/screenshots/csv_plaintext.png)

### Encrypted CSV
![csv Encrypt screenshot](Tugas-Kripto/screenshots/csv_encrypt.png)

---

# 📜 Lisensi
Bebas digunakan untuk tugas, praktikum, atau pembelajaran.

---
