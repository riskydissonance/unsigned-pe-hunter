mod trust;
mod metadata;

use std::env;
use colored::Colorize;
use walkdir::WalkDir;


fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() == 1 {
        println!("Usage: {} <root dir> [int x where find files in last x days]", &args[0]);
        return;
    }

    if args.len() == 3 {
        match args[2].parse::<u64>() {
            Ok(days) => {
                walk_path(args, days);
            }
            Err(_err) => {
                eprintln!("Expected an integer number of days for the second argument but got {}", args[2]);
                return;
            }
        }
    } else {
        walk_path(args, 0);
    }
}

fn walk_path(args: Vec<String>, days: u64) {
    let root_dir = &args[1];
    println!("Walking {}...", root_dir);

    for entry in WalkDir::new(root_dir) {
        match entry {
            Ok(entry) => {
                let path = entry.path().to_str().unwrap();
                if str::ends_with(&path, ".dll") || str::ends_with(&path, ".exe") {
                    unsafe {
                        process_file(path, days);
                    }
                }
            }
            Err(err) => {
                eprintln!("Error walking: {}", err);
                continue;
            }
        }
    }
}

unsafe fn process_file(path: &str, days: u64) {
    let creation_date = metadata::check_date(path, days);

    match creation_date {
        Ok(creation_date) => {
            if !creation_date.check {
                return;
            }
            let creation_time_string = creation_date.creation_date.format("%Y-%m-%d %H:%M:%S");
            let result = trust::check_cert(&path);

            match result {
                Ok(trust_data) => {
                    if !trust_data.valid {
                        println!("{} - {} - created UTC {}", &path, trust_data.message.red(), creation_time_string);
                    }
                    return;
                }
                Err(err) => {
                    eprintln!("{} - {}", &path, err);
                    return;
                }
            }
        }
        Err(err) => {
            eprintln!("{}", err);
            return;
        }
    }
}



