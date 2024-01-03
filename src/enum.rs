use sha2::digest::core_api::Block;
use threefish::{Threefish1024, Threefish256, Threefish512};
use threefish::cipher::{BlockDecrypt, BlockEncrypt};

use crate::fish::FResult;

pub(crate) enum Threefisher {
    Threefish256(Threefish256),
    Threefish512(Threefish512),
    Threefish1024(Threefish1024),
}

impl Threefisher {
    pub(crate) fn encrypt_block(&'static self, block: &mut Vec<u8>) -> FResult<bool> {
        /*
            * Encrypt the Given Block

            @param self: Threefisher Instance
            @param block: &mut Block<Threefish1024>
                * The block to encrypt
        */

        match self {
            Threefisher::Threefish256(threefish) => {
                let mut tf_block = Block::<Threefish256>::clone_from_slice(&block);
                threefish.encrypt_block(&mut tf_block);

                *block = tf_block.to_vec();
            }
            Threefisher::Threefish512(threefish) => {
                let mut tf_block = Block::<Threefish512>::clone_from_slice(&block);
                threefish.encrypt_block(&mut tf_block);

                *block = tf_block.to_vec();
            }
            Threefisher::Threefish1024(threefish) => {
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
            Threefisher::Threefish256(threefish) => {
                let mut tf_block = Block::<Threefish256>::clone_from_slice(&block);
                threefish.decrypt_block(&mut tf_block);

                *block = tf_block.to_vec();
            }
            Threefisher::Threefish512(threefish) => {
                let mut tf_block = Block::<Threefish512>::clone_from_slice(&block);
                threefish.decrypt_block(&mut tf_block);

                *block = tf_block.to_vec();
            }
            Threefisher::Threefish1024(threefish) => {
                let mut tf_block = Block::<Threefish1024>::clone_from_slice(&block);
                threefish.decrypt_block(&mut tf_block);

                *block = tf_block.to_vec();
            }
        }

        Ok(true)
    }
}