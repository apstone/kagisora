use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use anyhow::Result;
use argon2::{
    password_hash::{PasswordHash, SaltString},
    Argon2, PasswordHasher, PasswordVerifier,
};
use base64::{engine::general_purpose, Engine as _};
use clap::{Parser, Subcommand};
use rand::rngs::OsRng;
use rand::RngCore;
use rpassword::read_password;
use rusqlite::{params, Connection};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};

#[derive(Parser, Debug)]
#[command(
    name = "Kagisora",
    version = "1.0",
    about = "A tiny password manager - not to be taken seriously",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Add a new password entry
    Add {
        service: String,
        username: String,
        password: String,
    },
    /// Retrieve a password entry
    Get { service: String },
    /// Remove a password entry
    Remove { service: String },
    /// Start interactive shell
    Interactive,
}

fn derive_key(master_password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let argon2 = Argon2::default();

    let mut key = [0u8; 32];
    argon2.hash_password_into(master_password.as_bytes(), salt, &mut key)?;
    Ok(key)
}

fn save_salt_and_hash(salt: &[u8], hash: &str) -> Result<()> {
    let mut file = File::create("kagisora.dat")?;
    file.write_all(salt)?;
    file.write_all(hash.as_bytes())?;
    Ok(())
}

fn load_salt_and_hash() -> Result<(Vec<u8>, String)> {
    let mut file = OpenOptions::new().read(true).open("kagisora.dat")?;

    let mut salt = vec![0u8; 16];
    file.read_exact(&mut salt)?;

    let mut hash_str = String::new();
    file.read_to_string(&mut hash_str)?;
    Ok((salt, hash_str))
}

fn encrypt_data(key: &[u8; 32], data: &[u8]) -> Result<String> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(&key[..12]); // Use first 12 bytes of the key as nonce

    let ciphertext = cipher.encrypt(nonce, data)?;
    Ok(general_purpose::STANDARD.encode(ciphertext))
}

fn decrypt_data(key: &[u8; 32], ciphertext: &str) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(&key[..12]);

    let decoded_ciphertext = general_purpose::STANDARD.decode(ciphertext)?;
    let plaintext = cipher.decrypt(nonce, decoded_ciphertext.as_ref())?;
    Ok(plaintext)
}

fn add_password(
    conn: &Connection,
    service: &str,
    username: &str,
    password: &str,
    key: &[u8; 32],
) -> Result<()> {
    let data = format!("{}:{}", username, password);
    let encrypted_data = encrypt_data(key, data.as_bytes())?;

    conn.execute(
        "INSERT OR REPLACE INTO password_store (service, data) VALUES (?1, ?2)",
        params![service, encrypted_data],
    )?;

    println!("Password for '{}' added!", service);
    Ok(())
}

fn get_password(conn: &Connection, service: &str, key: &[u8; 32]) -> Result<()> {
    let mut stmt = conn.prepare("SELECT data FROM password_store WHERE service = ?1")?;
    let mut rows = stmt.query(params![service])?;

    if let Some(row) = rows.next()? {
        let encrypted_data: String = row.get(0)?;
        let decrypted_data = decrypt_data(key, &encrypted_data)?;
        let data_str = String::from_utf8(decrypted_data)?;
        let parts: Vec<&str> = data_str.splitn(2, ':').collect();

        if parts.len() == 2 {
            println!("Service: {}", service);
            println!("Username: {}", parts[0]);
            println!("Password: {}", parts[1]);
        } else {
            println!("Data format error for service '{}'", service);
        }
    } else {
        println!("No entry found for service '{}'", service);
    }

    Ok(())
}

fn remove_password(conn: &Connection, service: &str) -> Result<()> {
    let affected = conn.execute(
        "DELETE FROM password_store WHERE service = ?1",
        params![service],
    )?;

    if affected > 0 {
        println!("Password for '{}' removed.", service);
    } else {
        println!("No password found for service '{}'.", service);
    }

    Ok(())
}

fn list_services(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("SELECT service FROM password_store ORDER BY service")?;
    let service_iter = stmt.query_map([], |row| row.get::<_, String>(0))?;

    println!("Stored services:");
    for service in service_iter {
        println!("- {}", service?);
    }

    Ok(())
}

fn print_help() {
    println!("Available commands:");
    println!("  add <service> <username> <password> - Add a new password entry");
    println!("  get <service>                      - Retrieve a password entry");
    println!("  remove <service>                   - Remove a password entry");
    println!("  list                               - List all stored services");
    println!("  help                               - Show this help message");
    println!("  exit, quit                         - Exit the interactive shell");
}

fn run_interactive_shell(conn: &Connection, key: &[u8; 32]) -> Result<()> {
    println!("Entering interactive mode. Type 'help' for a list of commands.");

    loop {
        print!("kagisora> ");
        io::stdout().flush()?; // Ensure the prompt is displayed

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        if input.is_empty() {
            continue;
        }

        // Split the input into command and arguments
        let mut parts = input.split_whitespace();
        let command = parts.next().unwrap();
        let args: Vec<&str> = parts.collect();

        match command.to_lowercase().as_str() {
            "add" => {
                if args.len() != 3 {
                    println!("Usage: add <service> <username> <password>");
                    continue;
                }
                let (service, username, password) = (args[0], args[1], args[2]);
                add_password(conn, service, username, password, key)?;
            }
            "get" => {
                if args.len() != 1 {
                    println!("Usage: get <service>");
                    continue;
                }
                let service = args[0];
                get_password(conn, service, key)?;
            }
            "remove" => {
                if args.len() != 1 {
                    println!("Usage: remove <service>");
                    continue;
                }
                let service = args[0];
                remove_password(conn, service)?;
            }
            "list" => {
                list_services(conn)?;
            }
            "help" => {
                print_help();
            }
            "exit" | "quit" => {
                println!("Exiting interactive mode.");
                break;
            }
            _ => {
                println!(
                    "Unknown command '{}'. Type 'help' for a list of commands.",
                    command
                );
            }
        }
    }

    Ok(())
}

fn create_table(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS password_store (
            id INTEGER PRIMARY KEY,
            service TEXT NOT NULL UNIQUE,
            data TEXT NOT NULL
        )",
        [],
    )?;
    Ok(())
}

fn main() -> Result<()> {
    let args = Cli::parse();

    println!("Enter master password:");
    let master_password = read_password().expect("Failed to read master password");

    let (salt, stored_hash_str) = match load_salt_and_hash() {
        Ok(data) => data,
        Err(_) => {
            // First-time setup
            let mut salt = [0u8; 16];
            let mut rng = OsRng;
            rng.fill_bytes(&mut salt);

            let salt_string = SaltString::encode_b64(&salt)?;
            let argon2 = Argon2::default();
            let hash = argon2
                .hash_password(master_password.as_bytes(), &salt_string)?
                .to_string();
            save_salt_and_hash(&salt, &hash)?;
            println!("Master password set.");
            (salt.to_vec(), hash)
        }
    };

    // Parse the stored hash string into PasswordHash when verifying
    let stored_hash = PasswordHash::new(&stored_hash_str)?;

    // Verify master password
    let argon2 = Argon2::default();
    if argon2
        .verify_password(master_password.as_bytes(), &stored_hash)
        .is_err()
    {
        eprintln!("Invalid master password.");
        std::process::exit(1);
    }

    let key = derive_key(&master_password, &salt)?;

    let conn = Connection::open("kagisora.db")?;
    create_table(&conn)?;

    match args.command {
        Some(Commands::Add {
            service,
            username,
            password,
        }) => {
            add_password(&conn, &service, &username, &password, &key)?;
        }
        Some(Commands::Get { service }) => {
            get_password(&conn, &service, &key)?;
        }
        Some(Commands::Remove { service }) => {
            remove_password(&conn, &service)?;
        }
        Some(Commands::Interactive) | None => {
            run_interactive_shell(&conn, &key)?;
        }
    }

    Ok(())
}
