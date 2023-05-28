use std::fs::File;
use std::io::{Read, Write};
use std::num::NonZeroU32;
use std::ops::Div;
use std::path::{Path, PathBuf};
use std::process::exit;
use ring::pbkdf2;
use aes_gcm::{Aes256Gcm, KeyInit};
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::rand_core::RngCore;
use clap::{arg, Command};
use num_traits::{clamp, pow};
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

fn main(){
    let matches = Command::new("cryptonite")
        .version("0.0.1")
        .author("Víctor Alan")
        .about("A file encryption cli tool")
        .arg(
            arg!(-m --mode <MODE> "Sets either encryption (e) or decryption (d) mode").required(true)
        ).arg(
            arg!(-f --file <FILE> "Sets the file to encrypt/decrypt").required(true)
        )
        .arg(
            arg!(-p --password <PASSWORD> "Sets the password for encrypting/decrypting").required(true)
        )
        .arg(
            arg!(-s --salt <SALT> "Sets the salt for the password")
        )
        .arg(
            arg!(-b --blocksize <BLOCKSIZE> "Sets the block-size for encryption")
        ).get_matches();


    let mut block_size: usize = if matches.contains_id("blocksize") {
        matches.get_one::<String>("blocksize").unwrap().parse::<usize>().expect("invalid blocksize")
    } else {
        0
    };
    if block_size != 0 {
        if !block_size.is_power_of_two() {
            println!("Invalid block size");
            exit(0);
        }

        if block_size.ilog2() < 4 || block_size.ilog2() > 10 {
            println!("Invalid block size");
            exit(0);
        }
    }


    if let Some(operating_path) = matches.get_one::<String>("file"){
        let start = std::time::Instant::now();
        let mode = matches.get_one::<String>("mode").expect("No mode specified").to_lowercase();
        if mode == "e" || mode == "encryption" {

            let mut file = File::open(operating_path).expect("Invalid file");
            let filesize = file.metadata().unwrap().len();

            // Check if auto value is selected
            block_size = if block_size == 0 {
                // Approximation for optimal block-size
                clamp(filesize.ilog10() as usize + 1, 4, 10)
            } else { block_size };
            println!("Block-size set to {}", block_size);
            let password = matches.get_one::<String>("password").expect("Password not provided");


            let salt = if matches.get_one::<String>("salt").is_some() {matches.get_one::<String>("salt").unwrap().as_bytes()} else {b""};
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

            let path = Path::new(operating_path);
            let backup_path = PathBuf::from(path).to_str().unwrap().to_string() + ".encrypted";
            let mut newfile = File::create(backup_path).unwrap();
            let bytes: [u8; 1] = [block_size.ilog2() as u8];
            newfile.write(&bytes).expect("Unable to write at file");
            for (ciphertext, nonce) in encrypted_blocks {
                newfile.write_all(&nonce).expect("Error writing nonce");
                newfile.write_all(&ciphertext).expect("Error writing ciphertext");
            }
            println!("Took {:?}ms to encrypt {:?} bytes", start.elapsed().as_millis(), newfile.metadata().unwrap().len())
        } else if mode == "d" || mode == "decryption" {
            let mut file = File::open(operating_path).expect("Invalid file");
            let password = matches.get_one::<String>("password").expect("Password not provided");
            let salt = if matches.get_one::<String>("salt").is_some() {matches.get_one::<String>("salt").unwrap().as_bytes()} else {b""};
            let mut buffer = Vec::new();

            file.read_to_end(&mut buffer).expect("Error reading file");
            block_size = pow(2, buffer[0] as usize);
            println!("Block Size detected: {:?}", pow(2, buffer[0] as usize));
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

            let mut output_file_name: String = operating_path.to_string() + (".decrypted").as_ref();
            // Write the decrypted data to a file
            if operating_path.ends_with(".encrypted") {
                output_file_name = operating_path.strip_suffix(".encrypted").unwrap().to_string() + ".decrypted";
            }
            let mut output_file = File::create(output_file_name).expect("Error creating output file");
            output_file.write_all(&decrypted_data).expect("Error writing decrypted data");
            println!("Took {:?}ms to decrypt {:?} bytes", start.elapsed().as_millis(), decrypted_data.len())
        } else{
            println!("Invalid mode mode has to be either 'encryption' / 'e' or 'decryption' / 'd'");
            exit(0);
        }
    }
}
