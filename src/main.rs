extern crate winapi;

use std::ffi::CString;
use std::ffi::CStr;
use std::ptr::null_mut;
use std::mem;
use std::io::{Error, ErrorKind};

use winapi::um::processthreadsapi::PROCESS_INFORMATION;
use winapi::um::processthreadsapi::STARTUPINFOA;
use winapi::um::processthreadsapi::CreateProcessA;
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::shlobj::SHGetSpecialFolderPathA;

use winapi::um::shlobj::CSIDL_PROGRAM_FILESX86;
use winapi::shared::minwindef::FALSE;
use winapi::shared::minwindef::TRUE;
use winapi::shared::minwindef::MAX_PATH;

use winapi::um::tlhelp32::PROCESSENTRY32;
use winapi::um::tlhelp32::TH32CS_SNAPPROCESS;
use winapi::um::tlhelp32::CreateToolhelp32Snapshot;
use winapi::um::tlhelp32::Process32First;
use winapi::um::tlhelp32::Process32Next;

use winapi::um::winnt::PROCESS_QUERY_INFORMATION;
use winapi::um::winnt::PROCESS_VM_READ;

use winapi::um::psapi::GetModuleFileNameExA;

use winapi::um::handleapi::CloseHandle;
use winapi::shared::ntdef::HANDLE;

fn convert_to_string(input: * const std::os::raw::c_char) -> String
{
    unsafe 
    {
        let converted_string = CStr::from_ptr(input);
        let converted_string = converted_string.to_str().unwrap();
        let converted_string = converted_string.trim_matches(char::from(0));

        converted_string.to_string()
    }
}

fn get_running_steam_process() -> std::result::Result<String, Error>
{
    // Setup our process entry struct with the correct size...
    let mut entry: PROCESSENTRY32 = unsafe { mem::zeroed() };
    entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;

    unsafe 
    {
        // Get our snapshot...
        let snapshot: HANDLE = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        // Get our first entry...
        if Process32First(snapshot, &mut entry) == TRUE 
        {
            // Enumerate through all our processes...
            while Process32Next(snapshot, &mut entry) == TRUE
            {
                // Get our process name...
                let process_name = convert_to_string(entry.szExeFile.as_mut_ptr());

                // Check if it is Steam.exe
                let is_steam = process_name == "Steam.exe";

                // Continue the loop if it is not Steam...
                if !is_steam { continue; }

                ////////////////////////////////////
   
                println!("Found Steam; attempting to fetch additional information...");

                // Attempt to open our process for query...
                let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, entry.th32ProcessID);
                
                // Check if null...
                if process_handle.is_null() { return Err(Error::last_os_error()); }

                ////////////////////////////////////

                // Setup our process path with MAX_PATH (wrong)...
                let mut process_path = [0i8; MAX_PATH];

                // Get our module file name...
                let ret = GetModuleFileNameExA(process_handle, null_mut(), process_path.as_mut_ptr(), MAX_PATH as u32);

                // Cleanup!
                CloseHandle(process_handle);
                CloseHandle(snapshot);

                if ret == 0 
                { 
                    return Err(Error::last_os_error()); 
                }
                else 
                { 
                    println!("Successfully located Steam executable!",);
                    return Ok(convert_to_string(process_path.as_mut_ptr()));
                }
            }
        }

        // Close our handle...
        CloseHandle(snapshot);
    }

    Err(Error::new(ErrorKind::NotFound, "Steam process couldn't be found...")) 
}

/**
 * Finds the program files folder.
 */
fn find_program_files() -> std::result::Result<String, Error>
{
    let mut max_path = [0i8; MAX_PATH];

    let ret = unsafe 
    {
        SHGetSpecialFolderPathA(null_mut(), max_path.as_mut_ptr(), CSIDL_PROGRAM_FILESX86, TRUE)
    };

    if ret == 0 
    { 
        Err(Error::last_os_error()) 
    }
    else 
    {
        Ok(convert_to_string(max_path.as_mut_ptr())) 
    }
}

/**
 * Launches steam application.
 */
fn launch_steam() -> std::result::Result<i32, Error>
{
    let steam = get_running_steam_process().is_ok();
    println!("{}", steam);  

    // Our program files...
    let program_files = find_program_files().unwrap();

    // Setup our launch arguments...
    let arguments = CString::new(format!("{}\\Steam\\Steam.exe", program_files))
        .expect("Failed to convert CString...");

    
    // Setup our startup information and process information.
    let mut si: STARTUPINFOA = unsafe { mem::zeroed() };
    let mut pi: PROCESS_INFORMATION = unsafe { mem::zeroed() };

    // Update the cb value.
    si.cb = mem::size_of::<STARTUPINFOA>() as u32;

    // Attempt to create the process...
    let ret = unsafe 
    {
        CreateProcessA(
            null_mut(),
            arguments.as_ptr() as *mut i8,     
            null_mut(),          
            null_mut(),        
            FALSE,
            0, 
            null_mut(),
            null_mut(),
            &mut si,
            &mut pi 
        )
    };

    // Check if our opening of the process was successful.
    if ret == 0 
    { 
        Err(Error::last_os_error()) 
    }
    else 
    { 
        Ok(ret) 
    }
}

fn main() {
    launch_steam();

}