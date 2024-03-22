extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // println!("cargo:rustc-link-lib=log");
    // println!("cargo:rustc-link-lib=m");
    // println!("cargo:rustc-link-lib=dl");
    // println!("cargo:rustc-link-lib=unwind");
    println!("cargo:rustc-link-lib=c++_static");
    println!("cargo:rustc-link-lib=c++abi");
    // println!("cargo:rustc-link-lib=cliborc_rt-aarch64-android");
    // println!("cargo:rustc-link-lib=pthread");
    println!("cargo:rustc-link-lib=frida-gumjs");
    println!("cargo:rustc-cdylib-link-arg=-s");
    // println!("cargo:rustc-cdylib-link-arg=-ffunction-sections");
    // println!("cargo:rustc-cdylib-link-arg=-fdata-sections");
    // println!("cargo:rustc-cdylib-link-arg=-pthread");
    // println!("cargo:rustc-cdylib-link-arg=-Wl,-z,relro,-z,noexecstack,--gc-sections");
    // println!("cargo:rustc-cdylib-link-arg=-ffunction-sections -fdata-sections -pthread -Wl,-z,relro,-z,noexecstack,--gc-sections");


    let sys_root:String=env::var("SYSROOT").unwrap_or(String::from("/"));
    let target:String=env::var("TARGET").unwrap_or(String::from(""));

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let mut builder=bindgen::Builder::default().use_core();
    println!("sysroot:{}",sys_root);
    if sys_root!=""{
        builder=builder.clang_arg(format!("--sysroot={}",sys_root)).clang_arg(format!("--target={}",target))
    }
    println!("target:{}",target);
    let bindings = builder.header("wrapper.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .blocklist_type("GumChainedPtr64Rebase")
        .blocklist_type("GumChainedPtrArm64eRebase")
        .blocklist_type("_GumChainedPtr64Rebase")
        .blocklist_type("_GumChainedPtrArm64eRebase")
        .layout_tests(false)
        .generate_comments(false)
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(format!("{}\\src",env::var("CARGO_MANIFEST_DIR").unwrap()));
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}