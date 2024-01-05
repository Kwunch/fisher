use std::error::Error;
use std::path::PathBuf;

use rpassword;

use crate::fish::Fisher;

mod r#enum;
mod fish;

pub(crate) type FResult<T> = Result<T, Box<dyn Error>>;

const BLOCK_SIZES: [usize; 3] = [32, 64, 128];

fn main() -> FResult<()> {
    let args: Vec<String> = std::env::args().collect();

    /* Check if help is requested */
    if args.contains(&"--help".to_string()) || args.contains(&"-h".to_string())
        || args.contains(&"--HELP".to_string()) || args.contains(&"-H".to_string()) {
        print_help();
        return Ok(());
    }

    /* Check for encrypt or decrypt */
    let crypt = if args.contains(&"encrypt".to_string()) || args.contains(&"e".to_string())
        || args.contains(&"ENCRYPT".to_string()) || args.contains(&"E".to_string()) {
        true
    } else if args.contains(&"decrypt".to_string()) || args.contains(&"d".to_string())
        || args.contains(&"DECRYPT".to_string()) || args.contains(&"D".to_string()) {
        false
    } else {
        print_usage();
        return Ok(());
    };

    /* See if block size is specified */
    /* Get index of '--BLOCKSIZE' and add 1 to get index of block size */
    let block_size_index = args.iter().position(|x| x == "--BLOCKSIZE" || x == "-B"
        || x == "--blocksize" || x == "-b");
    let mut block_size = if block_size_index.is_some() {
        let bit_size = args[block_size_index.unwrap() + 1].parse::<usize>().unwrap();
        match bit_size {
            256 => 32,
            512 => 64,
            1024 => 128,
            _ => {
                /* Check if bit size is in BLOCK_SIZES array */
                if BLOCK_SIZES.contains(&bit_size) {
                    bit_size
                } else {
                    print_usage();
                    return Ok(());
                }
            }
        }
    } else {
        128
    };

    /* Get index of '-p'. Every index afterwards should be assumed to be a path */
    let path_index = args.iter().position(|x| x == "-p" || x == "-P");
    let tmp_paths = if path_index.is_some() {
        args[path_index.unwrap() + 1..].to_vec()
    } else {
        print_usage();
        return Ok(());
    };

    let mut paths: Vec<PathBuf> = Vec::new();
    /* Check if paths are valid */
    for path in tmp_paths {
        if !std::path::Path::new(&path).exists() {
            if path == "-v" || path == "-V" || path == "--verbose" || path == "--VERBOSE" {
                continue;
            }
            println!("Path '{:?}' does not exist", path);
            return Ok(());
        } else {
            /* Create path buffer and push to paths vector */
            let path_buf = PathBuf::from(path);
            paths.push(path_buf);
        }
    }

    /* Check if verbose is requested */
    let verbose: bool = args.contains(&"--verbose".to_string()) || args.contains(&"-v".to_string())
        || args.contains(&"--VERBOSE".to_string()) || args.contains(&"-V".to_string());

    /* Get password */
    let password = rpassword::prompt_password("Enter Password -> ").unwrap();
    /* Check if password is empty or if blank */
    if password.trim().is_empty() {
        println!("Password cannot be empty");
        return Ok(());
    }

    /* Get algorithm */
    let algorithm = if args.contains(&"blowfish".to_string()) || args.contains(&"bf".to_string())
        || args.contains(&"BLOWFISH".to_string()) || args.contains(&"BF".to_string())
        || args.contains(&"--bf".to_string()) || args.contains(&"--BF".to_string()) {
        block_size = 8;
        0
    } else if args.contains(&"twofish".to_string()) || args.contains(&"tw".to_string())
        || args.contains(&"TWOFISH".to_string()) || args.contains(&"TW".to_string())
        || args.contains(&"--tw".to_string()) || args.contains(&"--TW".to_string()) {
        block_size = 16;
        1
    } else if args.contains(&"threefish".to_string()) || args.contains(&"tf".to_string())
        || args.contains(&"THREEFISH".to_string()) || args.contains(&"TF".to_string())
        || args.contains(&"--tf".to_string()) || args.contains(&"--TF".to_string()) {
        2
    } else {
        println!("No algorithm specified");
        print_usage();
        return Ok(());
    };

    /* Create fisher instance */
    let fisher: &'static Fisher =
        Box::leak(Box::new(Fisher::new(algorithm, crypt, paths, password.to_string(), block_size, verbose)?));

    /* Run fisher */
    fisher.run()?;

    /* Notify user that fisher is done */
    println!("Finished!");

    Ok(())
}


pub(crate) fn print_usage() {
    /*
        * Print the Usage Message
    */

    println!("
        Usage: fisher [blowfish|twofish|threefish] [encrypt|decrypt] [optional block_size (threefish)] -p [paths] [optional verbose]
        fisher --help | -h: Print detailed help message
    ");
}

pub(crate) fn print_help() {
    println!("
        Fisher - Encrypt or Decrypt Files and Directories Using One of Three Algorithms
        - Blowfish
        - Twofish
        - Threefish

        Author: Kwunch

        Rust encryption program.
        Supports Blowfish, Twofish, and Threefish
        Blowfish is standard 64 bit block size
        Twofish is standard 128 bit block size
        Threefish supports 256, 512, and 1024 bit block sizes
            * Default block size for Threefish is 1024

        Block size should be passed as bytes, so 256 = 32, 512 = 64, 1024 = 128

        Usage: fisher [encrypt|decrypt] [optional block_size] -p [paths]
        Any string after -p will be treated as a path to encrypt or decrypt
        Recommended to put -p at the end of the command to avoid args being mistaken as paths

        Blowfish Encrypt and Decrypt Example:
            Encrypt: fisher --bf encrypt -p file.txt
            Decrypt: fisher --bf decrypt -p file.txt

        Twofish Encrypt and Decrypt Example:
            Encrypt: fisher --tw encrypt -p file.txt
            Decrypt: fisher --tw decrypt -p file.txt

        Threefish Encrypt and Decrypt Example:
            Encrypt: fisher --tf encrypt 32 -p file.txt
            Decrypt: fisher --tf decrypt 32 -p file.txt

        Args:
            blowfish  | bf | --bf: Use Blowfish
            twofish   | tw | --tw: Use Twofish
            threefish | tf | --tf: Use Threefish
            encrypt   | e: Encrypt the given file or directory
            decrypt   | d: Decrypt the given file or directory
            -p: The paths to encrypt or decrypt

        Flags:
            --help       | -h: Print this help message
            --version    | -v: Toggles verbose mode
            --BLOCK_SIZE | -B : The block size to use
    ")
}
