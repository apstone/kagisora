# Kagisora Password Manager

**Kagisora** is a simple and lightweight password manager built with Rust. It uses modern encryption techniques to securely store passwords, but it is not meant to be taken seriously as an enterprise-grade password management solution.

## Features

- **Add, retrieve, and remove password entries** stored securely using AES-256-GCM encryption.
- **Password-based key derivation** using Argon2 for secure password hashing.
- **Interactive shell mode** for easier management of stored passwords.
- **Salt and hash storage** for validating the master password.
- **SQLite-based storage** for password entries.

## Prerequisites

- **Rust** programming language installed on your system.
- **SQLite3** library installed on your system.

## Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd kagisora
   ```

2. **Build the project**:
   ```bash
   cargo build --release
   ```

3. **Run Kagisora**:
   ```bash
   cargo run
   ```

## Usage

Kagisora provides both **command-line options** and an **interactive shell** mode for managing your passwords.

### Command-line Options

1. **Add a new password entry**:
   ```bash
   cargo run -- add <service> <username> <password>
   ```
   Example:
   ```bash
   cargo run -- add example.com user123 my_secure_password
   ```

2. **Retrieve a password entry**:
   ```bash
   cargo run -- get <service>
   ```
   Example:
   ```bash
   cargo run -- get example.com
   ```

3. **Remove a password entry**:
   ```bash
   cargo run -- remove <service>
   ```
   Example:
   ```bash
   cargo run -- remove example.com
   ```

4. **Start the interactive shell**:
   ```bash
   cargo run -- interactive
   ```

### Interactive Shell

To enter the interactive shell, run:
```bash
cargo run -- interactive
```

The interactive shell allows you to use the following commands:

- `add <service> <username> <password>` - Add a new password entry.
- `get <service>` - Retrieve a password entry.
- `remove <service>` - Remove a password entry.
- `list` - List all stored services.
- `help` - Show the list of commands.
- `exit` or `quit` - Exit the interactive shell.

## Security

Kagisora uses the following security measures:

- **AES-256-GCM** for encrypting stored password entries.
- **Argon2** for deriving a secure key from the master password using a salt.
- Password entries are stored in an SQLite database named `kagisora.db`, and salt/hash information is stored in `kagisora.dat`.

### Important

Kagisora is a fun, lightweight project and is **not meant to be used as a serious security solution**. It lacks many features of established password managers, such as secure storage for the database, backup strategies, auditing, and advanced access controls.

## Development

Feel free to fork this project and improve it. If you encounter any issues or have suggestions for new features, please open an issue.

### Future Enhancements

Some potential improvements could include:
- Integration with more secure storage methods.
- Implementation of automatic backups and recovery mechanisms.
- Support for multi-factor authentication (MFA).

## License

This project is licensed under the MIT License.

