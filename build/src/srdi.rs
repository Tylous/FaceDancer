use dll2shell::shellcode;
use std::fs::File;
use std::io::Write;

pub fn create_srdi_payload(input: &str, function: &str) {
    let link_shellcode = shellcode::shellcode_rdi(&input, &function, "".to_string());
    let mut output_file = File::create("stuff.bin").expect("could not write file");
    output_file
        .write_all(&link_shellcode)
        .expect("could not write contents to output file");
    println!("[*] SRDI process completed");
}