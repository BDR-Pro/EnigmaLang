from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import random
import string
import sys
import ast
import marshal
import os
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style

colorama_init()

def ascii_art():
    print(r""" 
          


 _____       _                       _                      
| ____|_ __ (_) __ _ _ __ ___   __ _| |    __ _ _ __   __ _ 
|  _| | '_ \| |/ _` | '_ ` _ \ / _` | |   / _` | '_ \ / _` |
| |___| | | | | (_| | | | | | | (_| | |__| (_| | | | | (_| |
|_____|_| |_|_|\__, |_| |_| |_|\__,_|_____\__,_|_| |_|\__, |
               |___/                                  |___/ 


          
          """)
    

    print(r"""
          
          

===========================.========================================================================
===========================%%=============*==:=%@@@@@@@%%-:=========================================
=======================================%*+:.+#@@@@@@@@%@@@@@@@@=#*@%@@@@@@@-========================
===========+======================+#=--::-**+:-==%@@@@%#*-.+@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@==========
===========+===========+*##%%####@%=::-=@@@@@%%%%#%@@@%#%+---=+@%%@%%@@@*=@@@@@@@@@@@@@@@%%%-=======
====================%@@@%@:+%****%.#@@@@@@@@@%@@@@@@@@@@@@@%%%@@%####@@@@++*%%%@@@%*=--#-====**%===-
========++===========%%%%%@@@@@@@@@+%@@@@@@@@@@@@@@@@@@@@@%@%*@-%@@@@%##=%@@@@%+%%#****#*%%%%*%*==-=
+++++++++++++++===+++%#%%%%%%%%=-:*%#@@@@@@@@@@@@@@@@@@@@%@@#@%#@@@@%@@%-+%@@@@@@#@%#%%%%%%**%#%*%==
=+++=++++++++++++++++#%****#%%%%%#::=#@@@%%@@@@@@@@@@@@%%@@#%@@@@@@@@@@@@@@@@@@@@@@@%%%@%%+%###%#%%=
+++++++++++++++++++++##%%%#%%%%%%%%%*--@@@@@@@@@@@@@@%#@%@@@@@@@@@@%-@%#%@@%%%@%@%%%%#@%@@%%%%%@@@#=
=+=+=================%%%%%%#%%%%%%%%%%%#%+@@@@@@@@%@%%#+*.%%%%@@@@@@@@@@@@@@@%@%%%%####@@=%@%%*@@@%=
-------=------=----##@+=#@#=#%%@@%%%%%%%%%%%%#*---=*#%%%%%%%%@@@%@@%%%@@@@@@@@@%#******%#%+#%%=@@#==
--------------------@@%@@%@@@*++@%*%@@@@@%%%%%%%%%%%%%%%%%%%*#%%%%%%%##%%%%%%%#*******@@@%@#%-------
:::::::::::+---::*#%==-#@@@@@@@@%*#@-+=-%%%%@@@@%%%%%%%%%%%%%%%%%%%%%%@%%%%%%#********%*+@%%#+------
:::::::::::::@#:*@@@@@@##%@#==#@@@@@@%@@##%%@*==*%%@@@@%%%%%%%%%%%%%%%%%%%%%%*******%%%*@%#**-::::::
:::::::::::::+*#%#-=%@@@@@@@@@%.-.@%+.@@@@@%@@%@@%+:+%%%%%@@@@@%%%%%%%%%%%%%%******@#********:::::::
:::::::-#*#@@@@@@%%@:-=%@@@@@@@@@@%*#%@#--*@@@@@@@%@@@%*#%@@%##%@@@@@%%%%%%%%*%*@%#**********:::::::
::::::+**%@*==+@@@@@@@@%*#%+#=#@@@@@@@@##%@.:--%@@@@@@@@@%@@*##@@%***#@@@%@%%#@%####********-:::::-:
::::#+@@@@@#%@---=@:=@@@@@@###@*--=%@@@@@@@@@@@@=:=:@@@@@@@@@@@@@#*##**@%%%@%%#@#####*****%@%:::::::
:%%@@@@@@*+::@@-@%##%@=*.@@@#@@@%%@+---%@@@++@@@@@@@@+:--%@+*.@@@@@@@%%@@@@@@#%####@@####@@@%%-:::::
:=%@@@+:%%-+++*+***@@%%%%#-==@@@@@@@@@@@=:=:%@@@@@@@@@@@@@%#--*@@@@@@@@@@%@@@%%%%%%@%*%%*++++==-----
.###%:#==%@@%%:+++*@@@@@@%%%@#-*-%@@%@@@@%@@@-:-:#@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%%%%%++++++===----
.-#####%*:#@@@@@%%-+++*+**#@@%%%%----+@@%%@@@@@@@@=-=:-@@@@@@@@@@@@@@@@@@@%%%%%%%%%%%+++++++++===---
:-=+*%%%%%%%=@@@@@@@%%:****%*++@@@%%%@+--==@#@%@@@@%#%@@:----@@@@@@@@@@@@%%%%%%%%%%+++++++++========
::=++==-%%%%%%%%:@*##@@@%%:**#*#+++@@@%%%%%*#==#%@%@@@@@@##*%@@@@@@@@@@@@%%%%%@%%*+++++++++=========
::-====+=++%%%%%%%%*:@##@@@@%@:#####+++*@@@%%##%%@:=%#%@@@@@@@@@@@@@@@@@%%%%%%%%+++++++++===========
..::--====**%%%%%%%%%%@-@%#*@@@@%@-##****++**@@@@----=*:=+:@%@@@@@@@%@%%%%%%@@@#++++++++============
...:::---====+*#%%%%%%%%%%@:@@@@@@@@%@+***@@@***#%%%%%=:::::+@@%@#@@@%%%%%@@@@%%+++==============-=-
.....::::---====+**%%%%%%%%%%@%:@@@@@@@@@@@*#%%%+**@%%%***++%+#**@@@%%%%%@@@@%%+==================--
........::::---=====+*%%%%%%%%%%%@-@@@+++**+%#%*=**%*++*#***%*+++@@%%%%%#++++===================-==-
............:::----====+*#%%%%%%%%%%@@=@###=====+%%%%#==+***+*#%@%%%%%%*+++=======================-=
..............::::----====+**%*%%%%%%%%%@%-%###**====++#%*+==@+@%%%%%*+++======================-=---
.................::::----=====**%*%%%%%%%%%@@#-%+++****+++=@@@%%%%%+++++======================-=----
....................:::----======+*#%#%%@%%%%%%@@%%+===+*%@@@%%%%*++++==========================----
.....::::..........::::::::----=====+**%%*@@@@%%@@@@@@@@@@@@%%%#++++===========================-----
...::::.::.:......::::::::::::-----====+**##*%%@@@@@@@@@@@@@@*++++===================---==----------
::.::::::::::.:.:.::::.::::::::::----======+******@@@@@@@#+#++++================--------------------
.:::::::::.:::::::.:::::::::::::::::-----======**********+++===========-----------------------------
:::::::::::::::::.:::::::::::::::::::::----========================---------------------------------


          
          
          """)

def _help():
    print(f"Usage: {sys.argv[0]} <script_to_obfuscate.py> [--exe] [--sleep]")
    print("Welcome to the Python Obfuscator and Encryptor!\n")
    print("This tool will obfuscate and encrypt your Python scripts using AES encryption.\n")
    print("It will generate a new script that decrypts and executes the original code.\n")
    print("The decryption stub will be saved in a separate file.\n")
    print("The original script will be saved as bytecode.\n")
    print("The obfuscated script will be saved as a new Python file.\n")
    print("Optionally, you can compile the obfuscated script to an executable.\n")
    print("Optionally, you can add a Math based sleep function to the obfuscated script.\n")
    
    
def random_python_code():
    """Generates a random Python code snippet."""
    code = '\n'
    for _ in range(random.randint(1, 50)):
        code += f"{generate_random_string()} = {random.randint(1, 100)}\n"
        code += f"{generate_random_string()} = '{generate_random_string()}'\n"
        code += f"{generate_random_string()} = {random.choice([True, False])}\n"
        code += f"{generate_random_string()} = {random.random()}\n"
        code += f"{generate_random_string()} = {random.choice([None, 'None'])}\n"
        code += f"{generate_random_string()} = {random.choice([f'[\"{get_dummy_key()}\"]', f'{{\"{get_dummy_key()}\"}}', f'(\"{get_dummy_key()}\",)'])}\n"
        code += '\n'
        code += f"{generate_random_string()} = {random.choice([f'[\"{get_dummy_key()}\"]', f'{{\"{get_dummy_key()}\"}}', f'(\"{get_dummy_key()}\",)'])}\n"
        code += '\n'
    return code

def get_dummy_key():
    """get dummy aes key"""
    return get_random_bytes(32).hex()

def compile_to_bytecode(source_code):
    """Compiles Python source code to bytecode."""
    return compile(source_code, 'filename', 'exec')


def super_obfuscator():
    """Generates a random number of dummy functions and adds them to the code."""
    code = ''
    for _ in range(random.randint(1, 15)):
        code += add_dummy_code() + '\n'

    return code

class RenameVariables(ast.NodeTransformer):
    def __init__(self):
        self.renamed_vars = {}

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Store):  # Variable assignment
            if node.id not in self.renamed_vars:
                self.renamed_vars[node.id] = generate_random_string()
            node.id = self.renamed_vars.get(node.id)
        elif isinstance(node.ctx, ast.Load):  # Variable usage
            node.id = self.renamed_vars.get(node.id, node.id)
        return node

def change_variable_names(code):
    """Changes the names of variables in the code to random strings using AST parsing."""
    tree = ast.parse(code)
    tree = RenameVariables().visit(tree)
    new_code = ast.unparse(tree)  # Use astor.to_source(tree) for Python versions < 3.9
    return new_code
    
def generate_random_string(length=10):
    """Generates a random string of letters."""
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

def encrypt_data(data):
    """Encrypts a string using AES, outputting hexadecimal."""
    key = get_random_bytes(16)  # For AES-128
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    return cipher.iv.hex() + ct_bytes.hex()

def turn_string_to_list(input_string):
    """Converts a string to a list of strings."""
    return [input_string[i:i+70] for i in range(0, len(input_string), 70)]

def add_dummy_aes_func(my_word="", key="", encrypted_code=""):
    unique_id = generate_random_string()
    if not key or not encrypted_code:  # Generate dummy encrypted code and key if not provided
        dummy_code = "print('Hello from dummy AES func')"
        random_key = get_dummy_key()
        encrypted_code = encrypt_data(dummy_code)
    my_word=random_key if my_word == "" else my_word
    encrypted_code_str = f'"{encrypted_code}"'  # Now safely a base64-encoded string
    decryption_stub = f"""
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import sys
key = "{my_word}"
def decrypt_and_execute_{unique_id}(encrypted_code_hex):
    key_bytes = bytes.fromhex(key)
    encrypted_data_bytes = bytes.fromhex(encrypted_code_hex)
    iv = encrypted_data_bytes[:AES.block_size]
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    decrypted_code = unpad(cipher.decrypt(encrypted_data_bytes[AES.block_size:]), AES.block_size)
    decrypted_code = decrypted_code.decode('utf-8')
    exec(decrypted_code)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "{my_word}":
        decrypt_and_execute_{unique_id}({encrypted_code_str})
"""


    return decryption_stub
def add_dummy_def(sleep=False):
    """Generates a dummy function definition it call itself instead of sleep."""
    fun_name=generate_random_string()
    fun_call = f"{fun_name}()" if sleep else ""
    script = f"""
    def {fun_name}():\n    
        {random_math()}\n  
    {fun_call}\n
    """
    return script

def random_math():
    """Generates a random math operation."""
    return f"{random.randint(1, 100)} {''.join(random.choice(['+', '-', '*', '/']) + str(random.randint(1, 100)) for _ in range(random.randint(1, 5)))}"
def add_dummy_code(code=""):
    """Adds dummy code snippets to the given code."""
    sleep = True if "--sleep" in sys.argv else False
    time_to_sleep = random.randint(1, 500) if sleep else 5
    for _ in range(random.randint(1, time_to_sleep)):
        code += add_dummy_aes_func() + '\n'
        code += add_dummy_def(sleep) + '\n'
    return code
def name_of_file(file_path):
    return file_path.split('\\')[-1]


def print_usage_and_exit():
    print(f"Usage: {sys.argv[0]} <script_to_obfuscate.py> [--exe] [--sleep]")
    sys.exit(1)

def obfuscate_and_encrypt(file_path, key, my_word):
    with open(file_path, 'r') as file:
        original_code = file.read()

    obfuscated_code = add_dummy_code(original_code)
    encrypted_code = encrypt_data(obfuscated_code)
    decryption_stub = generate_decryption_stub(my_word, key, encrypted_code)
    
    return decryption_stub

def generate_decryption_stub(my_word, key, encrypted_code):
    decryption_stub = random_python_code()
    decryption_stub += super_obfuscator()
    decryption_stub += add_dummy_aes_func(my_word, key, encrypted_code)
    decryption_stub += random_python_code()
    decryption_stub += super_obfuscator()
    decryption_stub += random_python_code()
    decryption_stub = change_variable_names(decryption_stub)
    decryption_stub += random_python_code()
    return decryption_stub

def save_decryption_stub(decryption_stub, file_path):
    debugging = file_path.replace('.py', '_decryption_stub.py')
    with open(debugging, 'w') as f:
        f.write(decryption_stub)
    print(f"Debugging code in {Fore.GREEN}{name_of_file(debugging)}{Style.RESET_ALL}\n")
    return debugging

def save_bytecode(decryption_stub, file_path):
    bytecode = compile_to_bytecode(decryption_stub)
    bytecode_file_path = file_path.replace('.py', '_bytecode')
    with open(bytecode_file_path, 'wb') as f:
        marshal.dump(bytecode, f)
    print(f"Saving bytecode to {Fore.GREEN}{name_of_file(bytecode_file_path)}{Style.RESET_ALL}\n")
    return bytecode_file_path

def save_final_script(file_path, bytecode_file_name):
    new_file_path = file_path.replace('.py', '_obfuscated.py')
    final_code = '''
import marshal
import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))
with open("{}", 'rb') as f:
    loaded_bytecode = marshal.load(f)
exec(loaded_bytecode)
    '''.format(bytecode_file_name)
    with open(new_file_path, 'w') as new_file:
        new_file.write(final_code)
    print(f"Obfuscated and encrypted script saved to {Fore.GREEN}{name_of_file(new_file_path)}{Style.RESET_ALL}\n")
    return new_file_path

def compile_to_executable(file_path):
    os.system(f'pyinstaller --onefile {Fore.GREEN}{file_path}{Style.RESET_ALL}')
    print(f"Compiled {Fore.GREEN}{name_of_file(file_path)}{Style.RESET_ALL} to .exe")
    
def write_key_to_file(file_path,key):
    # write key to file in the same directory of the file path
    directory = os.path.dirname(file_path)
    file_path = os.path.join(directory, 'key.txt')
    with open(file_path, 'w') as f:
        f.write(key)
        
def sys_func():
    if len(sys.argv) < 2:
        print_usage_and_exit()
    if not os.path.exists(sys.argv[1]):
        print(f"Error: {Fore.RED}{sys.argv[1]}{Style.RESET_ALL} not found.")
        sys.exit(1)
    if not sys.argv[1].endswith('.py'):
        print(f"Error: {Fore.RED}{sys.argv[1]}{Style.RESET_ALL} is not a Python script.")
        sys.exit(1)
    if 'help' in sys.argv:
        ascii_art()
        _help()
        print_usage_and_exit()
    if '--sleep' in sys.argv:
        print("Adding Math based sleep function\n")

def main():
    ascii_art()
    sys_func()
    print("Loading... \n")
    file_path = sys.argv[1]
    decry_key = get_dummy_key()
    key = get_dummy_key()
    write_key_to_file(file_path,decry_key)
    print(f"Obfuscating and encrypting {Fore.GREEN}{name_of_file(file_path)}{Style.RESET_ALL}\n")
    decryption_stub = obfuscate_and_encrypt(file_path, key, decry_key)
    debugging_path = save_decryption_stub(decryption_stub, file_path)
    bytecode_file_path = save_bytecode(decryption_stub, file_path)
    new_file_path = save_final_script(file_path, name_of_file(bytecode_file_path))
    print(f"Decryption stub saved to {Fore.GREEN}{name_of_file(debugging_path)}{Style.RESET_ALL}\n")
    print(f"Bytecode saved to {Fore.GREEN}{name_of_file(bytecode_file_path)}{Style.RESET_ALL}\n")
    if '--exe' in sys.argv:
        compile_to_executable(new_file_path)

if __name__ == "__main__":
    main()
