import hashlib
import click
import requests
import pyperclip
import secrets


@click.command()
@click.argument('int_length', type=int)
def run(int_length):
    """Generates a random password using Python 3.6's secrets library, runs it through the SHA1 hashing algorithm, and checks it against
    haveibeenpwned.com's password range API. If the password is good, it conveniently copies it to the clipboard, if not, it runs recursively
    until it finds a good password (one that has not been found during any known data breaches."""
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
        run()
