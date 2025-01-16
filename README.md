# ElGamal File Encryption

A secure file encryption application using the ElGamal encryption algorithm with a graphical user interface. This implementation features mouse movement entropy for key generation and supports encryption of any file type including binary files (PDFs, images, etc.).

## Features

- **Secure Key Generation**: Uses mouse movement entropy for enhanced randomness in key generation
- **Profile Management**: Save and manage multiple encryption key profiles
- **Binary File Support**: Properly handles all file types including text, PDFs, images, and other binary files
- **Progress Tracking**: Visual feedback during encryption and decryption operations
- **User-Friendly Interface**: Simple GUI for all operations
- **Chunk-Based Processing**: Handles large files by processing them in chunks

## Requirements

- Python 3.8 or higher
- Required Python packages:
  ```
  tkinter
  sympy
  ```

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/elgamal-encryption.git
   cd elgamal-encryption
   ```

2. Install required packages:
   ```bash
   pip install sympy
   ```
   Note: tkinter usually comes with Python installation

## Usage

1. Run the application:
   ```bash
   python elgamal_file_encryptor.py
   ```

2. Generate new keys:
   - Click "Generate New Keys"
   - Move your mouse around the window to generate entropy
   - Enter a profile name to save the keys

3. Encrypt a file:
   - Select a key profile
   - Click "Encrypt File"
   - Choose the file to encrypt
   - Choose the destination for the encrypted file

4. Decrypt a file:
   - Select the same key profile used for encryption
   - Click "Decrypt File"
   - Choose the encrypted file
   - Choose the destination for the decrypted file

## Security Features

- **Entropy Collection**: Uses mouse movement patterns to enhance random number generation
- **Large Prime Numbers**: Generates cryptographically secure prime numbers for the encryption process
- **Secure Chunking**: Implements secure chunk processing with proper padding and length preservation
- **Profile Protection**: Safely stores encryption profiles with proper serialization

## Technical Details

### ElGamal Implementation
- Uses the ElGamal public-key cryptosystem
- Key generation based on discrete logarithm problem
- Implements chunking mechanism for handling files of any size
- Preserves file integrity through proper binary handling

### File Processing
- Chunks are processed with length preservation
- Proper padding mechanism for binary data
- Progress tracking for large file operations
- Error handling and validation

## Limitations

- Key size affects the maximum chunk size for encryption
- Encrypted files are slightly larger than original files due to the encryption overhead
- Key profiles are stored locally and should be backed up securely

## Security Considerations

1. **Key Storage**: 
   - Keep your profile files secure
   - Back up your profiles - lost keys mean unrecoverable files
   - Don't share private keys

2. **Usage**:
   - Use strong profile names for better organization
   - Keep track of which profile was used for encryption
   - Store encrypted files securely

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Based on the ElGamal encryption algorithm
- Uses the Sympy library for prime number generation
- Implements entropy collection through mouse movement

## Support

If you encounter any issues or have questions:
1. Check the existing issues on GitHub
2. Create a new issue with a detailed description of your problem
3. Include steps to reproduce the issue

## Disclaimer

This implementation is for educational purposes. While efforts have been made to ensure security, it should be reviewed thoroughly before use in production environments.
