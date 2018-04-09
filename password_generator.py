import hashlib
import fire
import requests
import pyperclip
import secrets


def run(int_length=24):
    password = generate_password(int_length)
    hashed_password = generate_hash(password)
    check_hash(password, hashed_password)



def generate_password(int_length):
    return (''.join(secrets.choice(
        'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890`~!@#$%^&*()-=+_:"/.,<>[]\{\}\\\'') for i in range(int_length)))


def generate_hash(str_password):
    str_password = str_password.encode('utf-8')
    sha1_obj = hashlib.sha1(str_password)
    hashed_password = sha1_obj.hexdigest()

    return hashed_password


def check_hash(password, hashed_password):
    first_five = hashed_password[0:5]
    remaining = hashed_password[5:]
    r = requests.get('https://api.pwnedpasswords.com/range/{}'.format(first_five))

    r_list = r.text.split('\r\n')
    hash_list = []
    for item in r_list:
        current_hash  = item.split(':')[0]
        if remaining in current_hash:
            print('Password has been hacked, generating new password.')
            run()
    pyperclip.copy(password)
    print('Found a good password, copied to clipboard.')


if __name__ == '__main__':
    fire.Fire(run)

