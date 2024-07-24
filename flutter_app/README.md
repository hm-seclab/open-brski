# Flutter App for useage with an ESP32 Pledge

This App communicates with an ESP32 over BLE connection. It's a flutter frontend with an on-device Rust backend.

The Rust backend is built with [flutter_rust_bridge](https://cjycode.com/flutter_rust_bridge/). The Rust backend lives in `<repository-root>/software/edulock-cli/crates/flutter_bridge`
By doing it this way, the Android app can reuse already implemented safe code via FFI bridge. 

### How to develop further

You will have to install the flutter_rust_bridge tool with cargo. When opening the `flutter_app` folder, you will need to run `flutter_rust_bridge_codegen` to generate new Rust bindings 
if you have changed anything in the backend. This part is a bit finnicky. You will have to make sure that:

- You are not *ever* using reference types in the public facing API of your FFI Rust code. Dart does not have the concept of `zero-copy`, so it can't work with `&str` slices. You will
need to allocate Strings every time
- You will have to make sure that every `third-party` package you'll be using *or returning* from your FFI api is re-exported via `pub use`

### What to watch out for

You should *never* touch any of the following files and folders yourself. These are either auto generated or come with `flutter_rust_bridge_codegen`

- Anything in `lib/src.rust/`
- Anything in `rust_builder`

You can also currently *only* debug this app via a connected Android phone. While it should work with Macos and iOS, I've not yet tested it.


