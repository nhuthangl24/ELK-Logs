Tat ca file trong thu muc nay la mau "giong thuc te":

1. ips_ids_flows.json
   - index 0,1,2: traffic binh thuong
   - index 3: mot lan SSH probe / brute-force probe tu Internet vao server noi bo
   Chay:
   & "..\.venv\Scripts\python.exe" main.py predict --input samples\ips_ids_flows.json

2. waf_requests.json
   - index 0,1: request hop le
   - index 2: SQL injection login bypass
   - index 3: XSS qua tham so q
   - index 4: SQL injection UNION SELECT
   Chay:
   & "..\.venv\Scripts\python.exe" main.py predict --input samples\waf_requests.json

3. waf_payloads.json
   - index 0,1: payload hop le
   - index 2,3,4: payload tan cong
   Chay:
   & "..\.venv\Scripts\python.exe" main.py predict --input samples\waf_payloads.json

4. pfsense_firewall.json
   - index 0,1: log Allowed hop le
   - index 2,3: log bi chan / bat thuong
   Chay:
   & "..\.venv\Scripts\python.exe" main.py predict --input samples\pfsense_firewall.json

5. pfsense_live_like.json
   - index 0,1: log block noi bo giong mau ban vua gui, thuong se ra benign
   - index 2: block SSH tu IP public vao server noi bo, de ra malicious hon
   - index 3: bogon / invalid TCP flags, de ra malicious hon
   Chay:
   & "..\.venv\Scripts\python.exe" main.py predict --input samples\pfsense_live_like.json

Doc ket qua:
   - prediction = 0  -> binh thuong
   - prediction = 1  -> dang nghi / tan cong
