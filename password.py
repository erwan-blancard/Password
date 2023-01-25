import json
import tkinter.messagebox
from tkinter import *
import hashlib as hash

SPECIAL_CHARS = "!?@#$%^&*"
LIST_FORMAT = "{} → {}"

CHECK_LABELS = [
    "Au moins 8 caractères",
    "Au moins une lettre majuscule",
    "Au moins une lettre minuscule",
    "Au moins un chiffre",
    "Au moins un caractère spécial ({})"
]

DEFAULT_KEYWORD = "Mot de passe"
FILEPATH = "passwords.json"

password_array = []


def get_char_for_state(condition):
    if condition:
        return "✓"
    return "✖"


def close_win(top):
    top.destroy()


def open_password_input_window():
    top = Toplevel(window)
    top.geometry("300x212")
    top.grab_set()
    top.resizable(width=False, height=False)
    label_password = Label(top, text="Entrez un mot de passe:")
    label_password.pack(pady=6)

    password_field = Entry(top)
    password_field.pack(pady=8)

    label_keyword = Label(top, text="Entrez un mot clé (optionnel):")
    label_keyword.pack(pady=6)

    keyword_field = Entry(top)
    keyword_field.pack(pady=8)

    button_validate = Button(top, text="Ajouter", command=lambda: check_password(top, keyword_field.get(), password_field.get()))
    button_validate.pack(pady=4)
    button_cancel = Button(top, text="Annuler", command=lambda: close_win(top))
    button_cancel.pack(pady=4)


def open_password_remove_window():
    response = tkinter.messagebox.askyesno("Confirmer", "Supprimer le(s) mot(s) de passe sélectionné(s) ?")
    if response:
        items = passwd_list.curselection()
        for item in items[::-1]:
            passwd_list.delete(item)
            password_array.pop(item)
        save_to_file()


def save_to_file():
    try:
        file = open(FILEPATH, "w")
        password_dict = {"passwords": password_array}
        json.dump(password_dict, file, indent=4)
        file.close()
    except Exception as e:
        tkinter.messagebox.showerror("Erreur !", "Les mots de passe n'ont pas été sauvegardés correctement:\n\n"+str(e))


def load_from_file():
    global password_array
    try:
        file = open(FILEPATH)
        # parse json to array
        json_array = json.load(file)
        password_array = json_array["passwords"]
        for items in password_array:
            passwd_list.insert(END, LIST_FORMAT.format(items[0], items[1]))
        file.close()
    except Exception as e:
        print(e)


def open_password_check_window(len_check, letter_up, letter_down, num_check, special_char_check):
    top = Toplevel(window)
    top.geometry("480x256")
    top.resizable(width=False, height=False)
    top.grab_set()
    label = Label(top, text="Le mot de passe saisi ne remplit pas une ou plusieurs de ces conditions:")
    label.pack(pady=12)
    label_len_check = Label(top, text=get_char_for_state(len_check) + " " + CHECK_LABELS[0])
    label_len_check.pack(pady=4)

    label_letter_up = Label(top, text=get_char_for_state(letter_up) + " " + CHECK_LABELS[1])
    label_letter_up.pack(pady=4)

    label_letter_down = Label(top, text=get_char_for_state(letter_down) + " " + CHECK_LABELS[2])
    label_letter_down.pack(pady=4)

    label_num_check = Label(top, text=get_char_for_state(num_check) + " " + CHECK_LABELS[3])
    label_num_check.pack(pady=4)

    label_special_char_check = Label(top, text=get_char_for_state(special_char_check) + " " + CHECK_LABELS[4].format(SPECIAL_CHARS))
    label_special_char_check.pack(pady=4)

    button_cancel = Button(top, text="Ok", command=lambda: close_win(top))
    button_cancel.pack(pady=16)


def check_password(top, keyword, password):
    if len(password) < 1:
        return
    if len(keyword) < 1:
        keyword = DEFAULT_KEYWORD
    len_check = False
    letter_up = False
    letter_down = False
    num_check = False
    special_char_check = False

    if len(password) >= 8:
        len_check = True

    for c in password:
        if c.isupper():
            letter_up = True
            break

    for c in password:
        if c.islower():
            letter_down = True
            break

    for c in password:
        if c.isnumeric():
            num_check = True
            break

    for c in password:
        if special_char_check:
            break
        for i in range(len(SPECIAL_CHARS)):
            if c == SPECIAL_CHARS[i]:
                special_char_check = True
                break

    if len_check and letter_up and letter_down and num_check and special_char_check:
        add_password(keyword, password)
        close_win(top)
    else:
        open_password_check_window(len_check, letter_up, letter_down, num_check, special_char_check)


def add_password(keyword, password):
    global password_array
    hashed_password = hash.sha256(password.encode())
    already_used = False
    for item in password_array:
        if item[1] == hashed_password.hexdigest():
            already_used = True
            break

    if not already_used:
        password_array += [[keyword, hashed_password.hexdigest()]]
        save_to_file()
        passwd_list.insert(END, LIST_FORMAT.format(keyword, hashed_password.hexdigest()))
    else:
        tkinter.messagebox.showwarning("Attention", "Le mot de passe saisi est déja utilisé")


window = Tk(className="Gestionnaire de mots de passe")
window.geometry("600x340")
window.resizable(width=False, height=False)

main_frame = Frame(window, padx=16, pady=16)
add_passwd_button = Button(main_frame, text="Ajouter un Mot de passe...", command=lambda: open_password_input_window())
add_passwd_button.pack()

passwd_list_frame = Frame(window, pady=16)
passwd_list = Listbox(passwd_list_frame, width=92, height=16)

load_from_file()

passwd_list.grid(column=0, row=0, sticky=(N, W, E, S))
scrollbar = Scrollbar(passwd_list_frame, orient=VERTICAL, command=passwd_list.yview)
scrollbar.grid(column=1, row=0, sticky=(N, S))
passwd_list['yscrollcommand'] = scrollbar.set
passwd_list_frame.grid_columnconfigure(0, weight=1)
passwd_list_frame.grid_rowconfigure(0, weight=1)

remove_passwd_button = Button(passwd_list_frame, text="Supprimer...", command=lambda: open_password_remove_window())
remove_passwd_button.grid(pady=10)

main_frame.pack()
passwd_list_frame.pack()

window.mainloop()