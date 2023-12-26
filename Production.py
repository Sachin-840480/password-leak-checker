#Making a password checking with a command line.
#------------------------------------------------#

#We are passing both the repsonse and tail (of hash we generate) into the leak_count().

#To check if the response 'hash' and tail matches, if it matches then get the count.

#We create a main() function to get the final value and get the output.

#We uses 'argv' to take the passwords from the command line.

'''-----------------------------------------------------------------------------------------------------'''


import requests
import hashlib
import sys

#hash for '123'
# '40BD0''01563085FC35165329EA1FF5C5ECBDBBEEF'


'''-----------------------------------------------------------------------------------------------------'''


# ( 1 ) Request data from the 'API Server' and 'checking' for the Correct 'response code'.

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char       #API url and '1st 5 characters of the Hash value.'
    res = requests.get(url)

    if res.status_code != 200:                                       #Checking the status code of the API, '200' Good, '400' Bad.
        raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again.')
    else:
        print(f'API Connection Secure. Starting to Fetch Data...')
    return res                                                       #returns the status code i.e (200) if ran successfully. 


'''-----------------------------------------------------------------------------------------------------'''


# ( 2 ) Check the Password, and Creating the 'HASH' for the pass in 'values'.

def pwned_api_check(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()  #hashing, encoding and covnvert to hexa-decimal, uppercase.

    first5_char, tail = sha1_password[:5], sha1_password[5:]        #spliting the 'HASH' value into 2 parts. ('1st' 5 chars, 'rest' chars).
#                                                                   # '40BD0' '01563085FC35165329EA1FF5C5ECBDBBEEF'

    response = request_api_data(first5_char)            #calling the (1) function and requesting the data for the '1st 5 character' values.

    return get_password_leak_count(response, tail)      # -> calling the (3) leak_count() function  with 2 values 'response' and 'tail'.
#                                                       # '<200>' {It has text data in it}  '01563085FC35165329EA1FF5C5ECBDBBEEF' {tail}
#                                                       # and return the count after all the processing.


'''-----------------------------------------------------------------------------------------------------'''


# ( 3 ) Counting the Number of times the a Hash Code was Leaked.

def get_password_leak_count(hashes, hash_to_check):  # -> It gets Values from 'response text <200>' and 'tail', i.e the 'rest characters'.

    hashes = (line.split(':') for line in hashes.text.splitlines())          #we use split(':') to split the 'key and value' pairs.

    for h, count in hashes:                 # 'h' = Hash values and 'count' = Number of times hacked.
#                                           # 'h' = 01563085FC35165329EA1FF5C5ECBDBBEEF  'count' = 1115142

        if h == hash_to_check:              #To Check :-  Hash values and Tail ('tail' from our own hash value's rest chars) 

            return count                    #If they match then return the Count Value.
        
        # return 0                          #It makes all the count '0'. {CAUTION}

    return 0                                #If found nothing then give '0'.


'''-----------------------------------------------------------------------------------------------------'''

#NOTES:-

# To do the calling of the functions we create a main() function.

# We get the values/arguments from the command line and we loop through them one by one and call 'pwned_api_check()' function while passing the values we get from the command line in it.

#------------------------------#

#After all the Processses :- 
# pwned_api_check(pass) ->  request_api_data(return) -> pwned_api_check(pass) -> get_password_leak_count(return) -> pwned_api_check(return)

# We get the count, i.e 'number of times the password was hacked'.

#---------------------------------------------------------------------------------------#

# ( 4 ) Calling the ' (2) pwned_api_check()' function and storing the count we get after all process.

def main(args):                            #It gets the values/arguments we pass from the Command Lines.

    for password in args:                  #Loop through all the arguemnts

        count = pwned_api_check(password)  #calls the ( 2 ) function and stores the count value after all the above mentioned processes.

        if count:                          #Simple if and Else part.             
            print(f'{password} was found {count} times... you should probably change your password.')
        else:
            print(f'{password} was not found. Carry on!')
    return 'done!'                         #this is not being printed because the program doesn't exit the file.
    
'''-----------------------------------------------------------------------------------------------------'''

# To get the values/arguments from the Command Lines.

main(sys.argv[1:])                      # Take input from the command line and pass it in the main function.
#                                       # It can take multiple arguments. 

#sys.exit(main(sys.argv[1:]))           #to make it exit we need to add sys.exit() to it.