use std::path::PathBuf;

use rpassword;

use crate::fish::*;

mod fish;
mod r#enum;

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
    let block_size = if block_size_index.is_some() {
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
            println!("Path '{:?}' does not exist", path);
            return Ok(());
        } else {
            /* Create path buffer and push to paths vector */
            let path_buf = PathBuf::from(path);
            paths.push(path_buf);
        }
    }

    /* Get password */
    let password = rpassword::prompt_password("Enter Password -> ").unwrap();
    /* Check if password is empty or if blank */
    if password.trim().is_empty() {
        println!("Password cannot be empty");
        return Ok(());
    }

    /* Create fisher instance */
    let fisher: &'static Fisher = Box::leak(Box::new(Fisher::new(crypt, paths, password, block_size)?));

    /* Run fisher */
    fisher.run()?;

    Ok(())
}
