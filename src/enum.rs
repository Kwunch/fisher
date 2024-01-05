use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use blowfish::Blowfish;
use blowfish::cipher::Key;
use sha2::{Digest, Sha256, Sha512};
use sha2::digest::core_api::Block;
use threefish::{cipher::KeyInit, Threefish1024, Threefish256, Threefish512};
use threefish::cipher::{BlockDecrypt, BlockEncrypt};
use twofish::Twofish;

use crate::FResult;

pub(crate) enum Fishers {
    Blowfish(Blowfish),
    Twofish(Twofish),
    Threefish256(Threefish256),
    Threefish512(Threefish512),
    Threefish1024(Threefish1024),
}

impl Fishers {
    pub(crate) fn encrypt_block(&'static self, block: &mut Vec<u8>) -> FResult<bool> {
        /*
            * Encrypt the Given Block

            @param self: Threefisher Instance
            @param block: &mut Block<Threefish1024>
                * The block to encrypt
        */

        match self {
            Fishers::Blowfish(blowfish) => {
                let mut bf_block = Block::<Blowfish>::clone_from_slice(&block);
                blowfish.encrypt_block(&mut bf_block);

                *block = bf_block.to_vec();
            }
            Fishers::Twofish(twofish) => {
                let mut tf_block = Block::<Twofish>::clone_from_slice(&block);
                twofish.encrypt_block(&mut tf_block);

                *block = tf_block.to_vec();
            }
            Fishers::Threefish256(threefish) => {
                let mut tf_block = Block::<Threefish256>::clone_from_slice(&block);
                threefish.encrypt_block(&mut tf_block);

                *block = tf_block.to_vec();
            }
            Fishers::Threefish512(threefish) => {
                let mut tf_block = Block::<Threefish512>::clone_from_slice(&block);
                threefish.encrypt_block(&mut tf_block);

                *block = tf_block.to_vec();
            }
            Fishers::Threefish1024(threefish) => {
                let mut tf_block = Block::<Threefish1024>::clone_from_slice(&block);
                threefish.encrypt_block(&mut tf_block);

                *block = tf_block.to_vec();
            }
        }

        Ok(true)
    }

    pub(crate) fn decrypt_block(&'static self, block: &mut Vec<u8>) -> FResult<bool> {
        /*
            * Decrypt the Given Block

            @param self: Threefisher Instance
            @param block: &mut Block<Threefish1024>
                * The block to decrypt
        */
        match self {
            Fishers::Blowfish(blowfish) => {
                let mut bf_block = Block::<Blowfish>::clone_from_slice(&block);
                blowfish.decrypt_block(&mut bf_block);

                *block = bf_block.to_vec();
            }
            Fishers::Twofish(twofish) => {
                let mut tf_block = Block::<Twofish>::clone_from_slice(&block);
                twofish.decrypt_block(&mut tf_block);

                *block = tf_block.to_vec();
            }
            Fishers::Threefish256(threefish) => {
                let mut tf_block = Block::<Threefish256>::clone_from_slice(&block);
                threefish.decrypt_block(&mut tf_block);

                *block = tf_block.to_vec();
            }
            Fishers::Threefish512(threefish) => {
                let mut tf_block = Block::<Threefish512>::clone_from_slice(&block);
                threefish.decrypt_block(&mut tf_block);

                *block = tf_block.to_vec();
            }
            Fishers::Threefish1024(threefish) => {
                let mut tf_block = Block::<Threefish1024>::clone_from_slice(&block);
                threefish.decrypt_block(&mut tf_block);

                *block = tf_block.to_vec();
            }
        }

        Ok(true)
    }
}

pub(crate) fn generate_key(alg: u8, block_size: usize, passphrase: String) -> FResult<Fishers> {
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

    match alg {
        0 => {
            let mut hasher = Sha512::default();
            hasher.update(passphrase.as_bytes());
            let hash = hasher.finalize();

            /* Truncate the hash to 448 bits */
            let hash = &hash[..56];

            Ok(Fishers::Blowfish(Blowfish::new(Key::<Blowfish>::from_slice(hash))))
        }
        1 => {
            let mut hasher = Sha256::default();
            hasher.update(passphrase.as_bytes());
            let hash = hasher.finalize();

            Ok(Fishers::Twofish(Twofish::new(Key::<Twofish>::from_slice(hash.as_slice()))))
        }
        2 => {
            match block_size {
                32 => {
                    /* Create 256 bit hash of the passphrase */
                    let mut hasher = Sha256::default();
                    hasher.update(passphrase.as_bytes());
                    let hash = hasher.finalize();
                    Ok(Fishers::Threefish256(Threefish256::new(Key::<Threefish256>::from_slice(hash.as_slice()))))
                }
                64 => {
                    /* Create 512 bit hash of the passphrase */
                    let mut hasher = Sha512::default();
                    hasher.update(passphrase.as_bytes());
                    let hash = hasher.finalize();
                    Ok(Fishers::Threefish512(Threefish512::new(Key::<Threefish512>::from_slice(hash.as_slice()))))
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
                    Ok(Fishers::Threefish1024(Threefish1024::new(Key::<Threefish1024>
                    ::from_slice(combined_hash.as_slice()))))
                }
                _ => {
                    Err("Invalid block size".into())
                }
            }
        }
        _ => {
            Err("Invalid algorithm".into())
        }
    }
}