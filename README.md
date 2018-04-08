# PyPass
PyPass is a simple Python 3 program that creates a random password utilizing all uppercase and lowercase letters, numbers, and all or mostly all special characters seen below:

`abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890~!@#$%^&*()-=+_:"/.,<>[]{}\'`

This program takes a password (defaulted at a length of 24 characters), hashes it using the SHA1 algorithm, and then passes it off to be verified against [haveibeenpwned's](https://api.pwnedpasswords.com/range) very own range API, their site can be found [here](https://www.haveibeenpwned.com), utilizing the [requests library](http://docs.python-requests.org/en/master/). If the password is not found in the list of known compromised passwords, it will return it and copy it to your clipboard for use, using [pyperclip](https://pyperclip.readthedocs.io/en/latest/introduction.html). 

**Note, if you are on Linux and receiving a Not Implemented Error, try `sudo apt-get install xclip`, that should solve the issue.**

## Prerequesites 
**use pip or pip3 respectively**

`pip install fire`

`pip install pyperclip`

`pip install requests`

### Work in progress
This program assumes you have working internet and all of that jazz, so there is currently minimal error handling, however, it will be improving over a period of time as I get time to work on it. :D. 