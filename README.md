# Malware Project

## Overview

This project demonstrates file encryption and decryption using the SharpAESCrypt library in C#. The project contains three main functionalities:
1. **Finder**: Lists all files and directories within a specified path.
2. **Encryptor**: Encrypts all files within the specified path.
3. **Decryptor**: Decrypts all files within the specified path.

**Note**: This project is created for educational purposes only and should not be used for any malicious intents. I am the sole creator of this project.

## Installation

1. **Clone the repository**:
    ```sh
    git clone https://github.com/yourusername/malware.git
    cd malware
    ```

2. **Install SharpAESCrypt**:
    Ensure you have the SharpAESCrypt NuGet package installed. You can install it via the NuGet Package Manager in Visual Studio:
    ```sh
    Install-Package SharpAESCrypt
    ```

## Usage

1. **Finder**:
    This function lists all files and directories within the specified path.
    ```csharp
    Finder();
    ```

2. **Encryptor**:
    This function encrypts all files within the specified path. It uses the SharpAESCrypt library for encryption.
    ```csharp
    Encryptor();
    ```

3. **Decryptor**:
    This function decrypts all files within the specified path. It uses the SharpAESCrypt library for decryption.
    ```csharp
    Decryptor();
    ```

## Configuration

You need to set the paths and encryption key in the code:
- `string Dir = @"(directory of your choosing)";`
- `string path = @"(directory of your choosing)";`
- `SharpAESCrypt.SharpAESCrypt.Encrypt("(your encryption key !DONT SHARE!)", file, encrypted_file);`
- `SharpAESCrypt.SharpAESCrypt.Decrypt("(your encryption key !DONT SHARE!)", file, decrypted_file);`

## Running the Program

1. Open the project in Visual Studio 2022.
2. Update the `Dir` and `path` variables in the `Finder`, `Encryptor`, and `Decryptor` functions with the appropriate directories.
3. Update the encryption key in the `Encryptor` and `Decryptor` functions.
4. Uncomment the function calls in the `Main` method based on what you want to run:
    ```csharp
    static void Main(string[] args)
    {
        // Decryptor();
        // Encryptor();
        Finder();
    }
    ```
5. Build and run the project.

## Notes

- This program is intended for educational purposes only. Please do not use it for any malicious activities.
- You can turn this program into a full-fledged application using control functions and the Visual Studio 2022 setup wizard solutions.

## Contributing

If you would like to contribute to this project, please fork the repository and create a pull request. For major changes, please open an issue to discuss what you would like to change.

## License

This project is licensed under the MIT License. See the LICENSE file for more information.

---

**Disclaimer**: This project is created for educational purposes only. The creator does not hold any responsibility for any misuse of this code.
