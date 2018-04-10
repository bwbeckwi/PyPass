import hashlib
import click
import requests
import pyperclip
import secrets
import csv


@click.command()
@click.argument('password_list', type=str, nargs=-1)
def test_passwords(password_list):
    if not password_list:
        return 'No password list provided.'
    else:
        for password in password_list:
            hashed_password = generate_hash(password)
            check_hash(password, hashed_password)



def generate_hash(str_password):
    print('Hashing password...')
    str_password = str_password.encode('utf-8')
    sha1_obj = hashlib.sha1(str_password)
    hashed_password = sha1_obj.hexdigest()

    return hashed_password


def check_hash(password, hashed_password):
    print('Checking hash against the pwned passwords API...')
    first_five = hashed_password[0:5]
    remaining = hashed_password[5:]
    r = requests.get('https://api.pwnedpasswords.com/range/{}'.format(first_five))
    r_list = r.text.split('\r\n')
    hash_list = []
    for item in r_list:
        current_hash  = item.split(':')[0]
        if remaining in current_hash:
            print('Password "{}" has been hacked.'.format(password))

    print('Password "{}" is good.'.format(password))

if __name__ == '__main__':
    test_passwords()


