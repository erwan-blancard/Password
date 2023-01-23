import hashlib as hash

NUMBERS = "0123456789"
SPECIAL_CHARS = "!@#$%^&*"

CHECK_LABELS = [
    "Au moins 8 caractères",
    "Au moins une lettre majuscule",
    "Au moins une lettre minuscule",
    "Au moins un chiffre",
    "Au moins un caractère spécial ({})"
]


def getcharstate(condition):
    if condition:
        return '\33[34m'+"✓"+'\033[0m'
    return '\33[31m'+"✖"+'\033[0m'


valid = False

while not valid:

    len_check = False
    letter_up = False
    letter_down = False
    num_check = False
    special_char_check = False

    password = input("Entrez un mot de passe: ")

    if len(password) >= 8:
        len_check = True

    for c in password:
        if c == c.upper():
            letter_up = True
            break

    for c in password:
        if c == c.lower():
            letter_down = True
            break

    for c in password:
        if num_check == True:
            break
        for i in range(len(NUMBERS)):
            if c == NUMBERS[i]:
                num_check = True
                break

    for c in password:
        if special_char_check == True:
            break
        for i in range(len(SPECIAL_CHARS)):
            if c == SPECIAL_CHARS[i]:
                special_char_check = True
                break

    # print password checks
    print("\n\t-", getcharstate(len_check), CHECK_LABELS[0])
    print("\t-", getcharstate(letter_up), CHECK_LABELS[1])
    print("\t-", getcharstate(letter_down), CHECK_LABELS[2])
    print("\t-", getcharstate(num_check), CHECK_LABELS[3])
    print("\t-", getcharstate(special_char_check), CHECK_LABELS[4].format(SPECIAL_CHARS), end="\n\n")

    if len_check and letter_up and letter_down and num_check and special_char_check:
        valid = True
        hashed_password = hash.sha256(password.encode())
        print("Le mot de passe crypté est:", hashed_password.hexdigest())