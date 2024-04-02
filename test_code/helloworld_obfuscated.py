
import marshal
import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))
with open("helloworld_bytecode", 'rb') as f:
    loaded_bytecode = marshal.load(f)
exec(loaded_bytecode)
    