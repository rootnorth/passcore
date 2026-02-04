import os
import json
import secrets
import string
import datetime
import maskpass
import base64
import subprocess

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.fernet import Fernet, InvalidToken
except Exception:
    print("Bu program 'cryptography' ve 'maskpass' kütüphanesine ihtiyaç duyar.")
    print("Kurmak için: pip install cryptography, pip install maskpass veya programın yanında gelen startme.bat'ı çalıştırın.")
    raise

PLAINTEXT_FILE = "passwords.json"
ENC_FILE = "passwords.enc"
SALT_SIZE = 16
KDF_ITERATIONS = 390000

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_bytes(data: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key_from_password(password, salt)
    f = Fernet(key)
    token = f.encrypt(data)
    return salt + token

def decrypt_bytes(salt_and_token: bytes, password: str) -> bytes:
    if len(salt_and_token) < SALT_SIZE:
        raise ValueError("Şifrelenmiş dosya beklenenden kısa.")
    salt = salt_and_token[:SALT_SIZE]
    token = salt_and_token[SALT_SIZE:]
    key = derive_key_from_password(password, salt)
    f = Fernet(key)
    return f.decrypt(token)

def load_data_encrypted(master_password: str):
    if os.path.exists(ENC_FILE):
        try:
            with open(ENC_FILE, "rb") as f:
                content = f.read()
            data_bytes = decrypt_bytes(content, master_password)
            return json.loads(data_bytes.decode("utf-8"))
        except InvalidToken:
            print("Hata: Master parola yanlış veya dosya bozulmuş.")
            raise
        except Exception as e:
            print("Şifreli dosya okunurken hata:", e)
            raise
    if os.path.exists(PLAINTEXT_FILE):
        try:
            with open(PLAINTEXT_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            print("Eski plaintext passwords.json bulundu. Veriler şifreleniyor ve passwords.enc oluşturuluyor...")
            save_data_encrypted(data, master_password)
            try:
                os.remove(PLAINTEXT_FILE)
                print("passwords.json silindi (migrasyon tamamlandı).")
            except Exception:
                print("passwords.json silinemedi; lütfen manuel kontrol edin.")
            return data
        except Exception as e:
            print("passwords.json okunurken hata:", e)
            return []
    return []

def save_data_encrypted(entries, master_password: str):
    try:
        raw = json.dumps(entries, ensure_ascii=False, indent=2).encode("utf-8")
        enc = encrypt_bytes(raw, master_password)
        with open(ENC_FILE, "wb") as f:
            f.write(enc)
    except Exception as e:
        print("Veri şifrelenip kaydedilirken hata:", e)
        raise

def generate_password(length=12, charset="all"):
    if length < 4:
        raise ValueError("Şifre uzunluğu en az 4 olmalidir.")
    
    letters = string.ascii_letters
    digits = string.digits
    symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?/"

    if charset == "letters":
        alphabet = letters
    elif charset == "letters_digits" or charset == "digits":
        alphabet = letters + digits
    else:
        alphabet = letters + digits + symbols  

    pwd = []
    if "letters" in charset or charset == "all" or charset == "letters_digits":
        pwd.append(secrets.choice(letters))

    if charset in ["letters_digits", "all", "digits"]:
        pwd.append(secrets.choice(digits)) 

    if charset == "all":   
        pwd.append(secrets.choice(symbols))

    while len(pwd) < length:
        pwd.append(secrets.choice(alphabet))

    secrets.SystemRandom().shuffle(pwd)
    return ''.join(pwd)

def create_password_flow(entries, master_password):
    print("\n--- PASSCORE ---")
    site = input("Site URL veya isim: ").strip()
    if not site:
        print("Site bilgisi boş olamaz.")
        return
    
    username = input("Kullanıcı adı (eposta): ").strip()
    if not username:
        print("Kullanıcı adı boş olamaz.")
        return
    
    try:
        length = int(input("Şifre uzunluğu (varsayılan 12): ") or 12)
    except ValueError:
        print("Geçersiz uzunluk değeri. Varsayılan 12 kullanılıyor.")
        length = 12

    print("Karakter seti seçenekleri:")
    print("1. Sadece harfler")      
    print("2. Harfler ve rakamlar")
    print("3. Harfler, rakamlar ve semboller (varsayılan)")
    choice = input("Seçiminiz (1/2/3): ").strip()
    if choice in ("1", "a","A"):
        charset = "letters"
    elif choice in ("2", "b", "B"):
        charset = "letters_digits"
    else:
        charset = "all"

    try:
        pwd = generate_password(length=length, charset=charset)
    except ValueError as e:
        print("Hata", e)
        return                   

    print(f"Oluşturulan şifre: {pwd}")

    entry = {
        "site": site,
        "username": username,
        "password": pwd,
        "created_at": datetime.datetime.now().isoformat() + "Z"
    }
    entries.append(entry)
    save_data_encrypted(entries, master_password)
    print("Şifre başarıyla kaydedildi. SIFRENIZ --->", ENC_FILE)

def show_saved_flow(entries, master_password):
    if not entries:
        print("\n[!] Kayıtlı şifre bulunmuyor.\n")
        return

    print("\n--- KAYITLI ŞİFRELER ---")
    print(f"{'No':<4} {'Site':<25} {'Kullanıcı':<25} {'Oluşturulma'}")
    print("-" * 80)
    for i, e in enumerate(entries, 1):
        site = (e.get('site') or '')[:25]
        user = (e.get('username') or '')[:25]
        created = e.get('created_at') or ''
        print(f"{i:<4} {site:<25} {user:<25} {created}")
    print("-" * 80)

    sel = input("\nDetaylı bilgi için şifre numarasını girin (iptal için ENTER): ").strip()
    if not sel:
        return
    try:
        idx = int(sel) - 1
        if idx < 0 or idx >= len(entries):
            print("Geçersiz numara.")
            return
    except ValueError:
        print("Geçersiz giriş.")
        return
    
    entry = entries[idx]
    print("\n--- KAYIT DETAYI ---")
    print(f"No: {idx+1}")
    print(f"Site: {entry.get('site')}")
    print(f"Kullanıcı adı: {entry.get('username')}")
    print(f"Şifre: {entry.get('password')}")
    print(f"Oluşturulma: {entry.get('created_at')}")

    choice = input("\nBu kaydı silmek ister misiniz? (e/h): ").strip().lower()
    if choice in ('e', 'evet', 'y', 'yes'):
        del entries[idx]
        save_data_encrypted(entries, master_password)
        print("Kayıt silindi.")

def run_requirements_bat():
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
    except Exception:
        base_dir = os.getcwd()
    bat_path = os.path.join(base_dir, "requirements.bat")
    if not os.path.exists(bat_path):
        return
    try:
        if os.name == "nt":
            subprocess.run(bat_path, shell=True, check=False)
        else:
            subprocess.run([bat_path], shell=True, check=False)
    except Exception as e:
        print("requirements.bat çalıştırılırken hata:", e)

def main():
    run_requirements_bat()
    print("""
░▒▓███████▓▒░ ░▒▓██████▓▒░ ░▒▓███████▓▒░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░░▒▓████████▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓███████▓▒░░▒▓████████▓▒░░▒▓██████▓▒░░▒▓██████▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓██████▓▒░   
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░     ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░     ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░▒▓███████▓▒░ ░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░                             
""")
    print("PASSCORE")
    master_password = input("Lütfen bir master parola girin (veya mevcut olanı kullanın): ").strip()
    if not master_password:
        print("Master parola boş olamaz.")
        return

    try:
        entries = load_data_encrypted(master_password)
    except InvalidToken:
        print("Master parola hatalı. Program kapatılıyor.")
        return
    except Exception as e:
        print("Veri yüklenirken beklenmedik hata:", e)
        return

    while True:
        print("\nMenu:")
        print(" 1) Şifre Oluştur")
        print(" 2) Kaydedilmiş şifreleri göster")
        print(" 3) Çıkış")
        choice = input("Seçiminiz: ")
        
        if choice in ["1", "a", "A"]:
            create_password_flow(entries, master_password)
        elif choice in ["2", "b", "B"]:
            show_saved_flow(entries, master_password)
        elif choice in ["3", "c", "C"]:
            print("Çıkış yapılıyor...")
            exit()
        else:
            print("Geçersiz seçim. Tekrar deneyin.")


if __name__ == "__main__":
    main()
