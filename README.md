# EnigmaLang 🕵️‍♂️

## Overview

EnigmaLang offers a sophisticated way to protect your Python scripts through obfuscation and encryption, turning your code into an unreadable format before execution. This tool is particularly useful for distributing Python applications without revealing the source code, making it a valuable asset for software developers concerned with protecting their intellectual property.

## Features

- **Code Obfuscation:** Transforms your Python script into an obfuscated version, making it difficult to reverse-engineer.
- **AES Encryption:** Encrypts the obfuscated script for an additional layer of security.
- **Decryption Stub:** Automatically generates a stub to decrypt and execute the encrypted code seamlessly.
- **Executable Compilation:** Offers an option to compile the obfuscated script into a standalone executable.

## Installation

1. Ensure Python 3 is installed on your machine.
2. Clone or download the EnigmaLang repository to your local machine.
3. Navigate to the EnigmaLang directory and install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

To protect your Python script using EnigmaLang, follow these steps:

1. Place your Python script in the `test_code` directory of EnigmaLang.
2. Run the main EnigmaLang script, specifying your script name:

   ```bash
   python main.py test_code/yourscript.py <SecretWord> <EncryptionIterations> [--exe] [--sleep]
   ```

    - Replace `yourscript.py` with the name of your Python script.
    - `<SecretWord>` is a secret word of your choosing that will be required to execute the encrypted script.
    - `<EncryptionIterations>` is the number of times the encryption process should be applied.

3. EnigmaLang will generate several files within the `test_code` directory:
   - An obfuscated version of your script.
   - A bytecode file containing the encrypted script.
   - A decryption stub in Python for decrypting and executing the encrypted script.

## Example

Suppose you have a simple Python script named `helloworld.py` with the following content:

```python
print("Hello World")
```

After running EnigmaLang, your `test_code` directory will contain:

- `helloworld_obfuscated.py`: The obfuscated version of `helloworld.py`.
- `helloworld_bytecode`: The encrypted bytecode of the obfuscated script.
- `helloworld_decryption_stub.py`: A Python script that, when executed, decrypts `helloworld_bytecode` and runs the original `helloworld.py` script.
- `helloworld.py`: The original script (unchanged).

To execute the encrypted script, simply run the decryption stub:

```bash
python helloworld_decryption_stub.py <SecretWord> <EncryptionIterations>
```

## Project Structure

```plaintext

EnigmaLang/
│
├── main.py
├── words_alpha.txt
├── requirements.txt
│
└── test_code/
    ├── helloworld_bytecode
    ├── helloworld_decryption_stub.py
    ├── helloworld_obfuscated.py
    └── helloworld.py
```

## Contributing

We welcome contributions to improve EnigmaLang! Please feel free to submit pull requests or open issues to suggest features or report bugs.

## License

EnigmaLang is open-sourced under the MIT license. See the LICENSE file for more details.
