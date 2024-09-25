use goblin::pe::PE;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

pub fn GenerateExports(path: &str) {
    let path = Path::new(&path);
    let mut file = File::open(&path).expect("Failed to open file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Failed to read file");
    match PE::parse(&buffer) {
        Ok(pe) => {
            let exports = pe.exports;
            let dll_name = path.file_stem().unwrap().to_str().unwrap();
            let mut def_content = String::new();
            def_content.push_str(&format!("LIBRARY \"{}\"\n", dll_name));
            def_content.push_str("EXPORTS\n");

            for (i, export) in exports.iter().enumerate() {
                if let Some(name) = &export.name {
                    def_content.push_str(&format!("    {}={}.{} @{}\n", name, dll_name, name, i + 1));
                }
            }
            let def_path = format!("{}.def", dll_name);
            let mut def_file = File::create(&def_path).expect("Failed to create .def file");
            def_file.write_all(def_content.as_bytes()).expect("Failed to write to .def file");
            println!("DLL Name: {}", dll_name);
            println!("Number of Exports: {}", exports.len());
            println!("DEF file generated at: {}", def_path);
        },
        Err(err) => eprintln!("Failed to parse PE file: {:?}", err),
    }
}
pub fn ListExports(path: &str) {
    let path = Path::new(path);
    let mut file = File::open(path).expect("Failed to open file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Failed to read file");

    match PE::parse(&buffer) {
        Ok(pe) => {
            let dll_name = path.file_stem().unwrap().to_str().unwrap();
            println!("DLL Name: {}", dll_name);
            println!("Exports:");

            for export in pe.exports.iter() {
                println!("- {}", export.name.unwrap_or("Unnamed"));
            }

            println!("Total Exports: {}", pe.exports.len());
        },
        Err(err) => eprintln!("Failed to parse PE file: {:?}", err),
    }
}