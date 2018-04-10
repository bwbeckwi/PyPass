import hashlib
import click
import requests
import pyperclip
import secrets
import csv


@click.group()
def cli():
    pass


@cli.command()
@click.argument('int_length', type=int)
@click.option('--int_num_pw', '-i' , default=1, type=int, help='Number of passwords to be generated.')
@click.option('--write/--no-write', default=False, help='Write to CSV or stdout.')
def generate_passwords(int_length, int_num_pw, write):
    """Generates a random password using Python 3.6's secrets library, runs it through the SHA1 hashing algorithm, and checks it against
    haveibeenpwned.com's password range API. If the password is good, it conveniently copies it to the clipboard (for single passwords),
    else it will print the list of paswords. If the password fails the test, a new one will be generated and returned."""
    password_list = []
    if int_num_pw == 1:
        password = create_password(int_length)
        hashed_password = generate_hash(password)
        check_hash(password, hashed_password, int_length, int_num_pw)
        pyperclip.copy(password)
        print('Copied password to clipboard.')
    elif int_num_pw > 1:
        while int_num_pw > 0:
            password = create_password(int_length)
            hashed_password = generate_hash(password)
            good_password = check_hash(password, hashed_password, int_length, int_num_pw)
            password_list.append(good_password)
            int_num_pw -= 1
        if write:
            print('\nPasswords have been written into "passwords.csv"\n')
            with open('passwords.csv', 'w', newline='') as csv_file:
                csv_writer = csv.writer(csv_file)
                for pw in password_list:
                    csv_writer.writerow([pw])
        else:
            print('\n\nPasswords are as follows:\n')
            for pw in password_list:
                print(pw)

    elif int_num_pw <= 0:
        return 'Error, number of passwords to be generated must be greater than zero.'


@cli.command()
@click.argument('password_list', type=str, nargs=-1)
def test_passwords():
    for password in password_list:
        hashed_password = generate_hash(password)
        check_hash(password, hashed_password, 0, 0)


def create_password(int_length):
    print('Generating password...')
    return (''.join(secrets.choice(
        'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890`~!@#$%^&*()-=+_:"/.,<>[]\{\}\\\'') for i in range(int_length)))


def generate_hash(str_password):
    print('Hashing password...')
    str_password = str_password.encode('utf-8')
    sha1_obj = hashlib.sha1(str_password)
    hashed_password = sha1_obj.hexdigest()

    return hashed_password


def check_hash(password, hashed_password, int_length, int_num_pw):
    print('Checking hash against the pwned passwords API...')
    first_five = hashed_password[0:5]
    remaining = hashed_password[5:]
    r = requests.get('https://api.pwnedpasswords.com/range/{}'.format(first_five))
    r_list = r.text.split('\r\n')
    hash_list = []
    for item in r_list:
        current_hash  = item.split(':')[0]
        if remaining in current_hash:
            if int_length:
                print('Password has been hacked, generating new password.')
                password = create_password(int_length)
                hashed_password = generate_hash(password)
                good_password = check_hash(password, hashed_password, int_length, int_num_pw)
                return good_password
            else:
                print('Password "{}" has been hacked.'.format(password))
        else:
            print('Password {} is good.'.format(password))
            return password


if __name__ == '__main__':
        cli()

