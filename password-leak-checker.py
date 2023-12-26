#making a password checking with a command line.

import requests
import hashlib
import sys

#hash for '123'
# '40BD0''01563085FC35165329EA1FF5C5ECBDBBEEF'

#running of the functions.
#pwned_api_check(pass) ->  request_api_data(return) -> pwned_api_check(pass) -> get_password_leak_count(return) -> pwned_api_check(return)

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error in API fetching, Status: {res.status_code}. Check the API and try again.')
    return res


def pwned_api_check(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1_password[:5], sha1_password[5:]
    response = request_api_data(first5_char)
    return get_password_leak_count(response, tail)


def get_password_leak_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0
    

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'Password: [{password}] was found: \"{count}\" times. | {{msg}}: You should probably change your password.')
        else:
            print(f'{password} was not found. Carry on!')
    return 'Done!'
    

# Only run this, if it's the 'main' file and not when it's being imported.

if __name__ == '__main__': 
    if len(sys.argv) < 2:           #Helps the user to run the file correctly.
        print("Usage: password-leak-checker.py <password 1> <password 2> ... ")
        sys.exit(1)
    sys.exit(main(sys.argv[1:]))    #just a fail-safe, to bring us back to the command line, if the program doesn't exit.
