#![no_std]
#![no_main]
extern crate panic_halt;

#[unsafe(no_mangle)]
unsafe fn _start() {
    unsafe {
        core::ptr::write_volatile(0x0 as *mut u64, 0x10 as u64);
    }
}
