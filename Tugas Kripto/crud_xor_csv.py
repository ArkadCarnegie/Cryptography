#!/usr/bin/env python3
"""
crud_xor_csv.py

Usage examples:

1) Convert plaintext CSV -> encrypted CSV and open it for CRUD:
   python3 crud_xor_csv.py -f input_plain.csv --key "my_secret_key" list

   This creates "input_plain_enc.csv" (encrypted storage) and runs `list`.

2) Use an already encrypted CSV for operations:
   python3 crud_xor_csv.py -F input_encrypted.csv --key "my_secret_key" get --id 2

3) Create a new row:
   python3 crud_xor_csv.py -F people_enc.csv --key "my_secret_key" create --data "id=3,name=Charlie,email=charlie@example.com,note=new"

4) Update:
   python3 crud_xor_csv.py -F people_enc.csv --key "my_secret_key" update --id 3 --data "note=updated"

5) Delete:
   python3 crud_xor_csv.py -F people_enc.csv --key "my_secret_key" delete --id 3

6) Dump MySQL:
   python3 crud_xor_csv.py -F people_enc.csv --key "my_secret_key" dump --table people_encrypted --out dump_encrypted.sql
"""

import argparse
import csv
import os
import base64
import hashlib
from typing import List, Dict, Optional

# ---------------------------
# Stream XOR utilities
# ---------------------------

def _sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def keystream_bytes(key: bytes, length: int, nonce: bytes = b"") -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        ctr_bytes = counter.to_bytes(8, "big")
        block = _sha256_bytes(key + nonce + ctr_bytes)
        out.extend(block)
        counter += 1
    return bytes(out[:length])

def xor_encrypt_bytes(plaintext: bytes, key: str, nonce: str = "") -> bytes:
    key_b = key.encode("utf-8") if isinstance(key, str) else key
    nonce_b = nonce.encode("utf-8") if isinstance(nonce, str) else nonce
    ks = keystream_bytes(key_b, len(plaintext), nonce_b)
    return bytes([p ^ k for p, k in zip(plaintext, ks)])

def encrypt_b64(plaintext_str: str, key: str, nonce: str = "") -> str:
    pt = (plaintext_str or "").encode("utf-8")
    ct = xor_encrypt_bytes(pt, key, nonce)
    return base64.b64encode(ct).decode("ascii")

def decrypt_b64_to_str(b64_cipher: str, key: str, nonce: str = "") -> str:
    if not b64_cipher:
        return ""
    try:
        ct = base64.b64decode(b64_cipher)
        pt = xor_encrypt_bytes(ct, key, nonce)  # symmetric
        return pt.decode("utf-8")
    except Exception:
        return "<decryption-error>"

# ---------------------------
# Encrypted CSV Table
# ---------------------------

class EncryptedCSVTable:
    def __init__(self, filepath: str, fields: List[str], key: str, encrypted_fields: Optional[List[str]] = None):
        self.filepath = filepath
        self.fields = fields
        self.key = key
        self.encrypted_fields = set(encrypted_fields or [f for f in fields if f != fields[0]])
        # ensure file exists
        if not os.path.exists(self.filepath):
            self._write_rows([])

    def _read_rows_raw(self) -> List[Dict[str,str]]:
        with open(self.filepath, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            return list(reader)

    def _write_rows(self, rows: List[Dict[str,str]]):
        with open(self.filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self.fields)
            writer.writeheader()
            for r in rows:
                writer.writerow(r)

    # CRUD
    def list(self) -> List[Dict[str,str]]:
        rows = self._read_rows_raw()
        out = []
        for r in rows:
            dec = {}
            for fld in self.fields:
                val = r.get(fld, "")
                if fld in self.encrypted_fields and val != "":
                    dec[fld] = decrypt_b64_to_str(val, self.key, r[self.fields[0]])
                else:
                    dec[fld] = val
            out.append(dec)
        return out

    def get(self, id_value: str) -> Optional[Dict[str,str]]:
        for r in self.list():
            if r[self.fields[0]] == id_value:
                return r
        return None

    def create(self, row: Dict[str,str]):
        rows = self._read_rows_raw()
        ids = [r[self.fields[0]] for r in rows]
        if row.get(self.fields[0]) in ids:
            raise ValueError("Duplicate id")
        stored = {}
        for fld in self.fields:
            val = row.get(fld, "")
            if fld in self.encrypted_fields and val != "":
                stored[fld] = encrypt_b64(val, self.key, row[self.fields[0]])
            else:
                stored[fld] = val
        rows.append(stored)
        self._write_rows(rows)

    def update(self, id_value: str, updates: Dict[str,str]) -> bool:
        rows = self._read_rows_raw()
        updated = False
        for r in rows:
            if r[self.fields[0]] == id_value:
                for k, v in updates.items():
                    if k in self.encrypted_fields and v != "":
                        r[k] = encrypt_b64(v, self.key, id_value)
                    else:
                        r[k] = v
                updated = True
                break
        if updated:
            self._write_rows(rows)
        return updated

    def delete(self, id_value: str) -> bool:
        rows = self._read_rows_raw()
        new_rows = [r for r in rows if r[self.fields[0]] != id_value]
        if len(new_rows) != len(rows):
            self._write_rows(new_rows)
            return True
        return False

    def dump_mysql_sql(self, table_name: str) -> str:
        lines = []
        lines.append(f"DROP TABLE IF EXISTS `{table_name}`;")
        col_defs = ",\n  ".join([f"`{c}` VARCHAR(1024)" for c in self.fields])
        lines.append(f"CREATE TABLE `{table_name}` (\n  {col_defs}\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;")
        rows = self._read_rows_raw()
        for r in rows:
            vals = []
            for c in self.fields:
                v = r.get(c, "")
                v_esc = v.replace("'", "''")
                vals.append(f"'{v_esc}'")
            lines.append(f"INSERT INTO `{table_name}` ({', '.join('`'+c+'`' for c in self.fields)}) VALUES ({', '.join(vals)});")
        return "\n".join(lines)

# ---------------------------
# Conversion helper
# ---------------------------

def convert_plain_to_encrypted(input_csv: str, output_csv: str, key: str, encrypted_fields: List[str], id_field: str = "id") -> List[str]:
    if not os.path.exists(input_csv):
        raise FileNotFoundError(f"Input not found: {input_csv}")
    with open(input_csv, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        fields = reader.fieldnames or []
    out_rows = []
    for r in rows:
        if id_field not in r:
            raise ValueError("id field missing in input CSV")
        rid = r[id_field]
        out_r = {}
        for fld in fields:
            val = r.get(fld, "")
            if fld in encrypted_fields and val != "":
                out_r[fld] = encrypt_b64(val, key, rid)
            else:
                out_r[fld] = val
        out_rows.append(out_r)
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for rr in out_rows:
            writer.writerow(rr)
    return fields

# ---------------------------
# CLI
# ---------------------------

def parse_keyvalue_pairs(s: str) -> Dict[str,str]:
    """
    Parse "k1=v1,k2=v2" into dict. Values may contain '=' or ',' if escaped? Simpler:
    split by comma, then split on first '='.
    """
    res = {}
    if not s:
        return res
    parts = s.split(",")
    for p in parts:
        if "=" in p:
            k, v = p.split("=", 1)
            res[k.strip()] = v.strip()
    return res

def main():
    p = argparse.ArgumentParser(description="CRUD over encrypted CSV using XOR stream")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file-plaintext", help="path to plaintext CSV to convert -> encrypted CSV")
    group.add_argument("-F", "--file-encrypted", help="path to already encrypted CSV to use directly")
    p.add_argument("--key", required=True, help="symmetric key (string) used for XOR stream")
    p.add_argument("--encrypt-fields", default="", help="comma-separated list of fields to encrypt (default: all except id)")
    # subcommands
    sub = p.add_subparsers(dest="cmd", required=True, help="command to run")

    sub.add_parser("list", help="list all rows (decrypted view)")

    get = sub.add_parser("get", help="get row by id")
    get.add_argument("--id", required=True, help="id value")

    create = sub.add_parser("create", help="create new row")
    create.add_argument("--data", required=True, help="data as k=v pairs separated by comma, e.g. id=3,name=Charlie")

    update = sub.add_parser("update", help="update row by id")
    update.add_argument("--id", required=True)
    update.add_argument("--data", required=True, help="k=v pairs")

    delete = sub.add_parser("delete", help="delete row by id")
    delete.add_argument("--id", required=True)

    dump = sub.add_parser("dump", help="dump storage to MySQL-compatible .sql file")
    dump.add_argument("--table", default="people_encrypted", help="table name for SQL dump")
    dump.add_argument("--out", default="dump_encrypted.sql", help="output SQL filename")

    args = p.parse_args()

    # Determine files and ensure encrypted CSV exists
    if args.file_plaintext:
        in_file = args.file_plaintext
        base = os.path.splitext(os.path.basename(in_file))[0]
        out_file = f"{base}_enc.csv"
        # determine fields from input CSV header
        if not os.path.exists(in_file):
            print(f"Error: plaintext input file not found: {in_file}")
            return
        with open(in_file, "r", newline="", encoding="utf-8") as fcsv:
            reader = csv.DictReader(fcsv)
            fields = reader.fieldnames or []
        if not fields:
            print("Error: input CSV has no header/fields")
            return
        # choose encrypted fields
        if args.encrypt_fields:
            enc_fields = [x.strip() for x in args.encrypt_fields.split(",") if x.strip()]
        else:
            enc_fields = [f for f in fields if f != fields[0]]  # all except id
        print(f"Converting plaintext {in_file} -> encrypted storage {out_file} (encrypt fields: {enc_fields})")
        fields = convert_plain_to_encrypted(in_file, out_file, args.key, enc_fields, id_field=fields[0])
        storage_file = out_file
    else:
        storage_file = args.file_encrypted
        if not os.path.exists(storage_file):
            print(f"Error: encrypted file not found: {storage_file}")
            return
        # read fields from file
        with open(storage_file, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            fields = reader.fieldnames or []
        if not fields:
            print("Error: encrypted CSV has no header")
            return
        if args.encrypt_fields:
            enc_fields = [x.strip() for x in args.encrypt_fields.split(",") if x.strip()]
        else:
            enc_fields = [f for f in fields if f != fields[0]]

    # instantiate table
    table = EncryptedCSVTable(storage_file, fields, args.key, encrypted_fields=enc_fields)

    # handle commands
    if args.cmd == "list":
        for r in table.list():
            print(r)

    elif args.cmd == "get":
        rec = table.get(args.id)
        if rec:
            print(rec)
        else:
            print(f"Not found id={args.id}")

    elif args.cmd == "create":
        data = parse_keyvalue_pairs(args.data)
        # ensure id present
        if fields[0] not in data:
            print(f"Error: must provide id field named '{fields[0]}' in data")
            return
        # fill missing fields with ""
        row = {fld: data.get(fld, "") for fld in fields}
        try:
            table.create(row)
            print("Created.")
        except ValueError as e:
            print("Error:", e)

    elif args.cmd == "update":
        data = parse_keyvalue_pairs(args.data)
        ok = table.update(args.id, data)
        print("Updated." if ok else "Not found / not updated.")

    elif args.cmd == "delete":
        ok = table.delete(args.id)
        print("Deleted." if ok else "Not found / not deleted.")

    elif args.cmd == "dump":
        sql = table.dump_mysql_sql(args.table)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(sql)
        print(f"Wrote SQL dump to {args.out}")

if __name__ == "__main__":
    main()
