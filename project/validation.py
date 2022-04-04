# Reference :: https://stackoverflow.com/questions/2990654/how-to-test-a-regex-password-in-python
# https://stackabuse.com/flask-form-validation-with-flask-wtf/

from re import fullmatch, search

def emailValidation(email):
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return fullmatch(regex, email)

def nameValidation(name):
    regex = r'[A-Za-z]{2,25}( [A-Za-z]{2,25})?'
    return len(name) <= 30 and fullmatch(regex, name)

def passwordValidation(password):
    regex = r'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$'
    return fullmatch(regex, password)