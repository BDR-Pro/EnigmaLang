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
    
    print("Welcome to the Python Obfuscator and Encryptor!\n")
    print("This tool will obfuscate and encrypt your Python scripts using AES encryption.\n")
    print("It will generate a new script that decrypts and executes the original code.\n")
    print("The decryption stub will be saved in a separate file.\n")
    print("The original script will be saved as bytecode.\n")
    print("The obfuscated script will be saved as a new Python file.\n")
    print("Optionally, you can compile the obfuscated script to an executable.\n")
    print("Optionally, you can add a Math based sleep function to the obfuscated script.\n")
    
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
def random_python_code():
    """Generates a random Python code snippet."""
    code = '\n'
    for _ in range(random.randint(1, 50)):
        code += f"{generate_random_string()} = {random.randint(1, 100)}\n"
        code += f"{generate_random_string()} = '{generate_random_string()}'\n"
        code += f"{generate_random_string()} = {random.choice([True, False])}\n"
        code += f"{generate_random_string()} = {random.random()}\n"
        code += f"{generate_random_string()} = {random.choice([None, 'None'])}\n"
        code += f"{generate_random_string()} = {random.choice([f'[\"{oxford_dictionary_word()}\"]', f'{{\"{oxford_dictionary_word()}\"}}', f'(\"{oxford_dictionary_word()}\",)'])}\n"
        code += '\n'
        code += f"{generate_random_string()} = {random.choice([f'[\"{oxford_dictionary_word()}\"]', f'{{\"{oxford_dictionary_word()}\"}}', f'(\"{oxford_dictionary_word()}\",)'])}\n"
        code += '\n'
    return code

def oxford_dictionary_word():
    """Returns a random word from the Oxford dictionary."""
    return random.choice(open('words_alpha.txt').read().split())

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

def encrypt_string(input_text, key,itr=random.randint(1, 10)):
    """Encrypts a string using AES."""
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted = cipher.encrypt(pad(input_text.encode('utf-8'), AES.block_size))
    for _ in range(itr):
        cipher = AES.new(key, AES.MODE_CBC)
        encrypted = cipher.encrypt(pad(encrypted, AES.block_size))
    return base64.b64encode(cipher.iv + encrypted).decode()

def turn_string_to_list(input_string):
    """Converts a string to a list of strings."""
    return [input_string[i:i+80] for i in range(0, len(input_string), 80)]

def add_dummy_aes_func(my_word="", key="", encrypted_code=""):
    """Generates a dummy AES decryption function with a random name and a new random key."""
    unique_id = generate_random_string()
    random_key =  base64.b64encode(get_random_bytes(32)).decode()
    encrypted_string = encrypt_string(random_python_code(), get_random_bytes(32))
    word = my_word if my_word else oxford_dictionary_word()
    key = key if key else random_key
    encrypted_code = encrypted_code if encrypted_code else encrypted_string
    encrypted_code = turn_string_to_list(encrypted_code)
    decryption_stub = f"""
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import sys
def turn_list_to_string(input_list):
    return ''.join(input_list)
    
encrypted_code = {encrypted_code}

# Decoding the key from Base64
key = base64.b64decode("{key}")

def decrypt_and_execute_{unique_id}(encrypted_code_b64, iteration):
    decrypted_code = ""
    for _ in range(iteration):
        encrypted_code_bytes = base64.b64decode(encrypted_code_b64)
        iv = encrypted_code_bytes[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_code = unpad(cipher.decrypt(encrypted_code_bytes[AES.block_size:]), AES.block_size)
        decrypted_code = decrypted_code.decode('utf-8')
    exec(decrypted_code)

if len(sys.argv) > 1 and sys.argv[1] == "{word}":
    decrypt_and_execute_{unique_id}(turn_list_to_string(encrypted_code), int(sys.argv[2]))
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
    sleep = True if "sleep" in sys.argv else False
    time_to_sleep = random.randint(1, 500) if sleep else 5
    for _ in range(random.randint(1, time_to_sleep)):
        code += add_dummy_aes_func() + '\n'
        code += add_dummy_def(sleep) + '\n'
    return code
def name_of_file(file_path):
    return file_path.split('\\')[-1]
def main():    
    ascii_art()
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <script_to_obfuscate.py> <Word To Run It> <Number of encryption itreator> [--exe] [--sleep]")
        sys.exit(1)
    print("Loading... \n")
    file_path = sys.argv[1]
    print(f"Obfuscating and encrypting {Fore.GREEN}{name_of_file(file_path)} {Style.RESET_ALL}\n")
    my_word = sys.argv[2]
    iteration = int(sys.argv[3])
    key = get_random_bytes(32)  # AES-128 key

    with open(file_path, 'r') as file:
        original_code = file.read()
    
    decryption_stub = ""
    # Obfuscate and encrypt the original code
    obfuscated_code = add_dummy_code(original_code)
    encrypted_code = encrypt_string(obfuscated_code, key,iteration)
    decryption_stub += random_python_code()
# Key handling: Convert 'key' to a Base64 string for embedding
    key_b64 = base64.b64encode(key).decode()
    decryption_stub += super_obfuscator() 
# Creating the decryption and execution stub
    decryption_stub += add_dummy_aes_func(my_word, key_b64, encrypted_code)
    decryption_stub += random_python_code()
    decryption_stub += super_obfuscator()
    decryption_stub += random_python_code()
    
    decryption_stub = change_variable_names(decryption_stub)
    decryption_stub += random_python_code()
    debugging=file_path.replace('.py', '_decryption_stub.py')
    with open(debugging, 'w') as f:
        f.write(decryption_stub)
    
    bytecode = (compile_to_bytecode(decryption_stub))
    bytecode_file_path = file_path.replace('.py', '_bytecode')
    bytecode_file_name = bytecode_file_path.split('\\')[-1]
    with open(bytecode_file_path, 'wb') as f:
        print(f"Saving bytecode to {Fore.GREEN}{name_of_file(bytecode_file_path)} {Style.RESET_ALL}\n")
        marshal.dump(bytecode, f)
    
    new_file_path = file_path.replace('.py', '_obfuscated.py')
    final_code = f'''
import marshal
import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))
with open("{bytecode_file_name}", 'rb') as f:
    loaded_bytecode = marshal.load(f)

# Step 4: Execute the loaded bytecode
exec(loaded_bytecode)
    
    '''
    with open(new_file_path, 'w') as new_file:
        new_file.write(str(final_code))

    print(f"Obfuscated and encrypted script saved to {Fore.GREEN}{name_of_file(new_file_path)} {Style.RESET_ALL}\n")
    print(f"Debugging code in {Fore.GREEN}{name_of_file(debugging)}{Style.RESET_ALL} \n")
    # Optionally compile to an executable
    if '--exe' in sys.argv:
        os.system(f'pyinstaller --onefile {Fore.GREEN}{new_file_path}{Style.RESET_ALL}')
        print(f"Compiled {Fore.GREEN}{name_of_file(new_file_path)}{Style.RESET_ALL} to .exe")

if __name__ == "__main__":
    main()
