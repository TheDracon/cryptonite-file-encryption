use std::fs::File;
use std::io::{Read, Write};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::process::exit;
use ring::pbkdf2;
use aes_gcm::{Aes256Gcm, KeyInit};
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aes::{Aes256Enc};
use clap::{App, Arg};
use num_traits::pow;
use ring::pbkdf2::PBKDF2_HMAC_SHA256;


fn derive_key_from_password(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut derived_key = [0u8; 32];
    let iterations = 100_000;
    pbkdf2::derive(
        PBKDF2_HMAC_SHA256,
        NonZeroU32::new(iterations).unwrap(),
        &salt,
        password.as_bytes(),
        &mut derived_key,
    );
    derived_key
}

fn encrypt_with_aes_gcm(key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12]), &'static str> {
    let key = GenericArray::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        nonce_bytes
    };
    let nonce = GenericArray::from_slice(&nonce);
    let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|_| "Encryption error")?;
    Ok((ciphertext, <[u8; 12]>::try_from(nonce.as_slice()).unwrap()))
}

fn decrypt_text_with_aes_gcm(key: &[u8], ciphertext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>, &'static str> {
    let key = GenericArray::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = GenericArray::from_slice(nonce);
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| "Decryption error")?;
    Ok(plaintext)
}

fn main() {
    let matches = App::new("File encryptor")
        .version("0.0.1")
        .author("Víctor Alan")
        .about("A command-line file encryption tool in rust")
        .arg(
            Arg::with_name("encrypt")
                .short("e")
                .long("encrypt")
                .value_name("FILE")
                .help("Sets the file to encrypt")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("decrypt")
                .short("d")
                .long("decrypt")
                .value_name("FILE")
                .help("Sets the file to decrypt")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("password")
                .short("p")
                .long("password")
                .value_name("PASSWORD")
                .help("Sets the password for encryption/decryption")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("salt")
                .short("s")
                .long("salt")
                .value_name("SALT")
                .help("Sets the salt for the password")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("block_size")
                .short("b")
                .long("block-size")
                .value_name("BLOCK_SIZE")
                .help("Sets the encryption block size")
                .takes_value(true)
        )
        .get_matches();
    let mut block_size: usize = if matches.is_present("block_size") { matches.value_of("block_size").unwrap().parse::<usize>().unwrap() } else { 16 };

    if !block_size.is_power_of_two() {
        println!("Invalid block size");
        exit(0);
    }

    if block_size.ilog2() < 4 || block_size.ilog2() > 8 {
        println!("Invalid block size");
        exit(0);
    }

    if matches.is_present("encrypt") && matches.is_present("decrypt"){
        println!("You cannot select encryption and decryption at the same time");
        exit(0)
    }
    if !matches.is_present("encrypt") && !matches.is_present("decrypt"){
        println!("You have to select decryption or encryption");
        exit(0)
    }
    let start = std::time::Instant::now();
    if let Some(encrypt_file) = matches.value_of("encrypt") {
        let password = matches.value_of("password").expect("Password not provided");
        let salt = if matches.value_of("salt").is_some() {matches.value_of("salt").unwrap().as_bytes()} else {b""};
        let mut file = File::open(encrypt_file).expect("Not a valid file");
        if file.metadata().unwrap().is_dir() {
            println!("File is a directory");
            exit(0)
        }

        let mut buffer = Vec::new();

        file.read_to_end(&mut buffer).expect("Error reading file");

        let key = derive_key_from_password(password, salt);

        let mut encrypted_blocks = Vec::new();

        for block in buffer.chunks(block_size) {
            let (ciphertext, nonce) = encrypt_with_aes_gcm(&key, block).unwrap();

            encrypted_blocks.push((ciphertext, nonce));
        }

        let path = Path::new(encrypt_file);
        let backup_path = PathBuf::from(path).to_str().unwrap().to_string() + ".encrypted";
        let mut newfile = File::create(backup_path).unwrap();
        let bytes: [u8; 1] = [block_size.ilog2() as u8];
        newfile.write(&bytes).expect("Unable to write at file");
        for (ciphertext, nonce) in encrypted_blocks {
            newfile.write_all(&nonce).expect("Error writing nonce");
            newfile.write_all(&ciphertext).expect("Error writing ciphertext");
        }
        println!("Took {:?}ms to encrypt {:?} bytes", start.elapsed().as_millis(), newfile.metadata().unwrap().len())

    }
    if let Some(decrypt_file) = matches.value_of("decrypt") {
        let password = matches.value_of("password").expect("Password not provided");
        let salt = if matches.value_of("salt").is_some() {matches.value_of("salt").unwrap().as_bytes()} else {b""};
        let mut file = File::open(decrypt_file).expect("Not a valid file");
        let mut buffer = Vec::new();

        file.read_to_end(&mut buffer).expect("Error reading file");
        block_size = pow(2, buffer[0] as usize);
        let key = derive_key_from_password(password, salt);

        let mut decrypted_data = Vec::new();
        let mut position = 1; // At one cause of block_size byte

        while position < buffer.len() {
            let nonce_length = 12;
            let nonce_bytes = &buffer[position..position + nonce_length];
            let nonce = <[u8; 12]>::try_from(nonce_bytes).expect("Invalid nonce size");

            let ciphertext_end = if position+nonce_length+block_size+16 > buffer.len() { buffer.len() } else { position+nonce_length+block_size+16 };
            let ciphertext_block = &buffer[position + nonce_length..ciphertext_end];
            let decrypted_block = decrypt_text_with_aes_gcm(&key, ciphertext_block, &nonce)
                .expect("Error decrypting block");

            decrypted_data.extend_from_slice(&decrypted_block);

            position += nonce_length + block_size+16;
        }

        let mut output_file_name: String = decrypt_file.to_string() + ".decrypted";
        // Write the decrypted data to a file
        if decrypt_file.ends_with(".encrypted") {
            output_file_name = decrypt_file.strip_suffix(".encrypted").unwrap().to_string() + ".decrypted";
        }
        let mut output_file = File::create(output_file_name).expect("Error creating output file");
        output_file.write_all(&decrypted_data).expect("Error writing decrypted data");
        println!("Took {:?}ms to decrypt {:?} bytes", start.elapsed().as_millis(), decrypted_data.len())
    }
}
