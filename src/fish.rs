use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::thread::JoinHandle;

use crate::r#enum::{Fishers, generate_key};

pub(crate) type FResult<T> = Result<T, Box<dyn Error>>;

pub(crate) struct Fisher {
    block_size: usize,
    crypt: bool,
    fisher: Fishers,
    paths: Vec<PathBuf>,
    verbose: bool,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl Fisher {
    pub(crate) fn new(algorithm: u8, crypt: bool, paths: Vec<PathBuf>, passphrase: String, block_size: usize, verbose: bool) -> FResult<Fisher> {
        /*
            * Create a new Fisher Instance

            @param crypt: bool
                * Whether to encrypt or decrypt
            @param paths: PathBuf
                * The path to the file or directory to encrypt or decrypt
            @param passphrase: String
                * The passphrase to encrypt or decrypt with
            @return FResult: Result<Fisher, Box<dyn Error>>
                * The Fisher instance or some Error
        */
        Ok(Fisher {
            block_size,
            crypt,
            fisher: generate_key(algorithm, block_size, passphrase)?,
            paths,
            threads: Mutex::new(Vec::new()),
            verbose,
        })
    }

    pub(crate) fn run(&'static self) -> crate::FResult<()> {
        /*
            * Run the Fisher on the Given Path

            @param self: Fisher Instance
            @return FResult: Result<(), Box<dyn Error>>
        */

        for path in &self.paths {
            let path = path.clone();
            match path.is_dir() {
                /* Iterate over the directory */
                true => {
                    if self.verbose {
                        println!("Got directory: {:?}", path);
                    }
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
                    if self.verbose {
                        println!("Got file: {:?}", path);
                    }
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

    fn iter_dir(&'static self, path: PathBuf) -> crate::FResult<()> {
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
                    if self.verbose {
                        println!("Got subdirectory: {:?}", module.path());
                    }
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

                    if self.verbose {
                        println!("Got file: {:?}", module.path());
                    }

                    /* Run modify_file() on the file */
                    self.modify_file(&module.path())?;
                }
            }
        }

        Ok(())
    }

    fn modify_file(&'static self, path: &PathBuf) -> crate::FResult<()> {
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

