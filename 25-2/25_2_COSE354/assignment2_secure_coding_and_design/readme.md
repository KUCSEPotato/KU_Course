# Introduction
In the case of Python, all five vulnerabilities are included in a single file named `app.py`, while in C, each vulnerable code is separated into individual files.
When submitting the assignment, please modify and submit `app.py + writeup` for Python, and `vulnerable1.c` to `vulnerable5.c + writeup` for C.
We will verify that the functionality works correctly and that the vulnerabilities are properly patched, so ensure that the functionality remains intact while accurately patching the vulnerabilities.

## python
**Goal:** Patch`app.py` 

**Vulnerability List**

1. SQL Injection
2. Cross Site Scripting
3. SSRF
4. Command Injection
5. Local File Inclusion (Directory traversal)

### env_python
## venv 설치
``` bash
python3 -m venv venv_vuln

source venv_vuln/bin/activate
```

## Method 2) Use python

1. Install python package (flask, requests)
    
    ```bash
    pip install Flask requests
    or
    pip3 install Flask requests
    ```
    
2. Go to problem(web) directory
    
    ![image.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/7e9f35bd-141d-4c1f-bc7a-573b844ce5dc/6f1318d6-6c29-47ff-bec7-2d50f6f75006/image.png)
    
3. Run command
    
    ```bash
    python3 app.py
    or
    python app.py
    ```
    
4. Go to url: `127.0.0.1:5000`

### 실행 에러
- 5000 포트를 사용중이라는 경우
``` bash
lsof -nP -iTCP:5000 -sTCP:LISTEN
-------------
COMMAND   PID   USER   ...  TCP *:5000 (LISTEN)
python3  12345 potato  ...

<------------>
kill 12345
# 그래도 안꺼지면 (강제)
kill -9 12345
```

## c
**Goal:** Patch `vulnerable1~5.c` 

**Vulnerability List**

- Integer Overflow
- Format String Bug
- Buffer overflow
- Race Condition

To see an example of how to attempt this exploit, refer to the "Sample Exploit (vulnerable1)" at the bottom of the page.