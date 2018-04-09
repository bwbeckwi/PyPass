# PyPass
PyPass is a simple Python 3 program that creates a random password utilizing all uppercase and lowercase letters, numbers, and all or mostly all special characters seen below:

`abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890~!@#$%^&*()-=+_:"/.,<>[]{}\'`

This program takes a password (defaulted at a length of 24 characters), hashes it using the SHA1 algorithm, and then passes it off to be verified against [haveibeenpwned's](https://api.pwnedpasswords.com/range) very own range API, their site can be found [here](https://www.haveibeenpwned.com), utilizing the [requests library](http://docs.python-requests.org/en/master/). If the password is not found in the list of known compromised passwords, it will return it and copy it to your clipboard for use, using [pyperclip](https://pyperclip.readthedocs.io/en/latest/introduction.html). 

**Note, if you are on Linux and receiving a Not Implemented Error, try `sudo apt-get install xclip`, that should solve the issue.**

## Prerequesites 
**use pip or pip3 respectively**, this project was built in python 3.5 and has not been otherwise tested.
**Update**, this project has now been updated to use python 3.6 to support the new library module [secrets](https://docs.python.org/3/library/secrets.html) which is used for generating cryptographically strong random numbers suitable for managing data such as passwords, account authentication, security tokens, and related secrets. This is a big step up from the original random class that was used in this project. If you are running a Linux OS that doesn't have python 3.6 installed, you will have to find that and install it first. I built this in Ubuntu 16.04, so if that's what you have as well, use the below commands to get python3.6

`sudo add-apt-repository ppa:jonathonf/python-3.6`

`sudo apt update`

`sudo apt install python3.6`

Then you can run python3.6 from a terminal to utilize this password generator instead of python3

`pip install fire`

`pip install pyperclip`

`pip install requests`

## Use
This project utilizes an unoffical Google package called [Fire](https://github.com/google/python-fire), it's sort of an auto CLI tool creator. Pretty awesome actually. Anyway, to run this program once you have everything downloaded and installed, use
`python3.6 password_generator.py run` in it's respective directory. 

### Work in progress
This program assumes you have working internet and all of that jazz, so there is currently minimal error handling, however, it will be improving over a period of time as I get time to work on it. :D. 


