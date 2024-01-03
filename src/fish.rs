use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::thread::JoinHandle;

use sha2::{Digest, Sha256, Sha512};
use threefish::{Threefish1024, Threefish256, Threefish512};
use threefish::cipher::{Key, KeyInit};

use crate::r#enum::Threefisher;

pub(crate) type FResult<T> = Result<T, Box<dyn Error>>;


pub(crate) struct Fisher {
    block_size: usize,
    crypt: bool,
    fisher: Threefisher,
    path: Vec<PathBuf>,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl Fisher {
    pub(crate) fn new(crypt: bool, path: Vec<PathBuf>, passphrase: String, block_size: usize) -> FResult<Fisher> {
        /*
            * Create a new Fisher Instance

            @param crypt: bool
                * Whether to encrypt or decrypt
            @param path: PathBuf
                * The path to the file or directory to encrypt or decrypt
            @param passphrase: String
                * The passphrase to encrypt or decrypt with
            @return FResult: Result<Fisher, Box<dyn Error>>
                * The Fisher instance or some Error
        */

        Ok(Fisher {
            block_size,
            crypt,
            fisher: generate_key(block_size, passphrase)?,
            path,
            threads: Mutex::new(Vec::new()),
        })
    }

    pub(crate) fn run(&'static self) -> FResult<()> {
        /*
            * Run the Fisher on the Given Path

            @param self: Fisher Instance
            @return FResult: Result<(), Box<dyn Error>>
        */

        for path in &self.path {
            let path = path.clone();
            match path.is_dir() {
                /* Iterate over the directory */
                true => {
                    println!("Got directory: {:?}", path);
                    /* Create new thread to run the directory */
                    {
                        let mut threads = self.threads.lock().unwrap();
                        threads.push(std::thread::spawn(move || {
                            self.iter_dir(path)
                                .expect("Failed to run directory");
                        }));
                    }
                }
                /* Modify the file */
                false => {
                    println!("Got file: {:?}", path);
                    self.modify_file(&path)?;
                }
            }
        }

        /* Wait for all threads to finish */
        loop {
            /* Lock the threads */
            let mut threads = self.threads.lock().unwrap();
            /* If there are are threads, pop the first, drop the lock, and join the thread */
            if threads.len() > 0 {
                /* Pop the first thread */
                let thread = threads.remove(0);
                /*
                    * Drop the lock before joining the thread
                    * Prevents deadlock if threads are still being spawned in run_dir()
                */
                drop(threads);
                /* Join the thread */
                thread.join().unwrap();
            } else {
                /* No threads left, break the loop (Lock drops on loop exit) */
                break;
            }
        }
        Ok(())
    }

    fn iter_dir(&'static self, path: PathBuf) -> FResult<()> {
        /*
            * Run the Fisher on the Given Directory

            @param self: Fisher Instance
            @param path: PathBuf
                * The path to the directory to encrypt or decrypt
            @return FResult: Result<(), Box<dyn Error>>
        */

        /* Iterate over the directory */
        for module in fs::read_dir(path)? {
            /* Get the module */
            let module = module?;

            match module.path().is_dir() {
                true => {
                    println!("Got subdirectory: {:?}", module.path());

                    /* Create new thread to run the subdirectory */
                    {
                        let mut threads = self.threads.lock().unwrap();
                        threads.push(std::thread::spawn(move || {
                            self.iter_dir(module.path())
                                .expect("Failed to run subdirectory");
                        }));
                    }
                }
                false => {
                    /* Modify the file */
                    /* On MAC, ignore .DS_Store */
                    if module.path().file_name().unwrap().eq(".DS_Store") {
                        continue;
                    }

                    println!("Got file: {:?}", module.path());

                    /* Run modify_file() on the file */
                    self.modify_file(&module.path())?;
                }
            }
        }

        Ok(())
    }

    fn modify_file(&'static self, path: &PathBuf) -> FResult<()> {
        /*
            * Modify [Encrypt or Decrypt] the Given File

            @param self: Fisher Instance
            @param path: &PathBuf
                * The path to the file to encrypt or decrypt

            @return FResult: Result<(), Box<dyn Error>>
        */
        let mut file = File::open(path)?;
        let mut buffer: Vec<u8>;

        /* Read the file into blocks */
        let mut modified_blocks: Vec<Vec<u8>> = Vec::new();

        loop {
            /* Create a new buffer */
            buffer = vec![0; self.block_size];
            /* Read the buffer size from the file */
            let bytes_read = file.read(&mut buffer)?;

            if bytes_read == 0 {
                /* End of file, break the loop */
                break;
            }

            /* Convert the buffer to a vector */
            let mut block: Vec<u8> = buffer.to_vec();

            if match self.crypt {
                /* True -> Encrypt */
                true => self.fisher.encrypt_block(&mut block)?,
                /* False -> Decrypt */
                false => self.fisher.decrypt_block(&mut block)?
            } {
                /* Push the modified block to the vector */
                modified_blocks.push(block.to_vec());
            } else {
                /* Failed to encrypt or decrypt the block */
                return Err("Failed to encrypt or decrypt block".into());
            }
        }

        /* Write the modified blocks to the file */
        let mut file = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)?;

        /* Iterate over the modified blocks writing each block */
        for block in &modified_blocks {
            if *block == modified_blocks.last().unwrap().to_vec() {
                /* Last block, clear padding */
                let mut padding = 0;
                for byte in block.iter().rev() {
                    if *byte == 0 {
                        padding += 1;
                    } else {
                        break;
                    }
                }
                /* Truncate the block */
                let block = &block[..block.len() - padding];
                file.write(&block)?;
                break;
            }

            file.write(&block)?;
        }

        Ok(())
    }
}

/*
    * Helper Functions

    * Generate a Key from the Given Passphrase
    * Print the Usage Message
    * Print the Help Message
*/

fn generate_key(block_size: usize, passphrase: String) -> FResult<Threefisher> {
    /*
        * Generate a Key from the Given Passphrase

        @param self: Fisher Instance
        @param passphrase: String
            * The passphrase to generate the key from
        @return FResult: Result<Key, Box<dyn Error>>
            * The generated key or some Error
    */

    /* Check if passphrase is actually a file, if so read the file and use that as the passphrase */
    let passphrase = match PathBuf::from(&passphrase).is_file() {
        true => {
            let mut file = File::open(passphrase)?;
            let mut passphrase = String::new();
            file.read_to_string(&mut passphrase)?;
            passphrase
        }
        false => passphrase
    };

    match block_size {
        32 => {
            /* Create 256 bit hash of the passphrase */
            let mut hasher = Sha256::default();
            hasher.update(passphrase.as_bytes());
            let hash = hasher.finalize();
            Ok(Threefisher::Threefish256(Threefish256::new(Key::<Threefish256>::from_slice(hash.as_slice()))))
        }
        64 => {
            /* Create 512 bit hash of the passphrase */
            let mut hasher = Sha512::default();
            hasher.update(passphrase.as_bytes());
            let hash = hasher.finalize();
            Ok(Threefisher::Threefish512(Threefish512::new(Key::<Threefish512>::from_slice(hash.as_slice()))))
        }
        128 => {
            /* Create 1024 bit hash of the passphrase */
            /* Combines 512 hash of original passphrase with 512 hash of the 512 hash */
            let mut hasher = Sha512::default();
            hasher.update(passphrase.as_bytes());
            let hash = hasher.finalize();
            let mut cct_hasher = Sha512::default();
            cct_hasher.update(hash.as_slice());
            let cct_hash = cct_hasher.finalize();
            /* Combine the two hashes */
            let mut combined_hash: [u8; 128] = [0; 128];
            combined_hash[..64].clone_from_slice(hash.as_slice());
            combined_hash[64..].clone_from_slice(cct_hash.as_slice());
            Ok(Threefisher::Threefish1024(Threefish1024::new(Key::<Threefish1024>
            ::from_slice(combined_hash.as_slice()))))
        }
        _ => {
            Err("Invalid block size".into())
        }
    }
}


pub(crate) fn print_usage() {
    /*
        * Print the Usage Message
    */

    println!("
        Usage: fisher [encrypt|decrypt] [optional block_size] -p [paths]
        fisher --help | -h: Print detailed help message
    ");
}

pub(crate) fn print_help() {
    println!("
        Fisher - Encrypt or Decrypt Files and Directories
        Author: Kwunch

        Threefish encryption implementation in Rust
        Supports 256, 512, and 1024 bit block sizes

        Block size should be passed as bytes, so 256 = 32, 512 = 64, 1024 = 128

        Usage: fisher [encrypt|decrypt] [optional block_size] -p [paths]
        Any string after -p will be treated as a path to encrypt or decrypt
        Recommended to put -p at the end of the command to avoid args being mistaken as paths

        Example: fisher encrypt password 32 -p file.txt
        Example: fisher decrypt password -p file.txt

        - Default block size is 1024

        Args:
            encrypt | e: Encrypt the given file or directory
            decrypt | d: Decrypt the given file or directory
            -p: The paths to encrypt or decrypt

        Flags:
            --help | -h: Print this help message
            --version | -v: Print the version
            --BLOCK_SIZE | -B : The block size to use
    ")
}