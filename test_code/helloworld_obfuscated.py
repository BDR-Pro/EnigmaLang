
import marshal
import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))
with open("helloworld_bytecode", 'rb') as f:
    loaded_bytecode = marshal.load(f)

# Step 4: Execute the loaded bytecode
exec(loaded_bytecode)
    
    