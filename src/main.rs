extern crate winapi;

use std::ffi::CStr;
use std::ffi::CString;
use std::io::{Error, ErrorKind, Read, Write};
use std::{mem, fs, io};
use serde::{Serialize, Deserialize};
use std::ptr::{null_mut};

use winapi::um::processthreadsapi::{CreateProcessA, OpenProcess, PROCESS_INFORMATION, STARTUPINFOA};
use winapi::um::shlobj::{SHGetSpecialFolderPathA, CSIDL_PERSONAL};
use winapi::shared::minwindef::{FALSE, MAX_PATH, TRUE};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS};
use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, PROCESS_TERMINATE};
use winapi::um::psapi::{GetModuleFileNameExA};
use winapi::shared::ntdef::{HANDLE};
use winapi::um::handleapi::{CloseHandle};

#[derive(Default, Serialize, Deserialize, Debug)]
struct Account
{
    nickname: String,
    username: String,
    password: String,
}

#[derive(Default, Serialize, Deserialize, Debug)]
struct Configuration
{
    steam_path: String,
    accounts: Vec<Account>,
    auto_close: bool,
}

const CONFIGURATION_FILE_NAME: &str = "\\steam_account_manager.cfg";

fn convert_to_string(input: *const std::os::raw::c_char) -> String
{
    unsafe {
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

    unsafe {
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
                    if !is_steam {
                        continue;
                    }

                    ////////////////////////////////////

                    // Attempt to open our process for query...
                    let process_handle = OpenProcess(
                        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE,
                        FALSE,
                        entry.th32ProcessID,
                    );

                    // Check if null...
                    if process_handle.is_null()
                    {
                        return Err(Error::last_os_error());
                    }

                    ////////////////////////////////////

                    // Setup our process path with MAX_PATH (wrong)...
                    let mut process_path = [0i8; MAX_PATH];

                    // Get our module file name...
                    let ret = GetModuleFileNameExA(
                        process_handle,
                        null_mut(),
                        process_path.as_mut_ptr(),
                        MAX_PATH as u32,
                    );

                    // Cleanup!
                    CloseHandle(process_handle);
                    CloseHandle(snapshot);

                    if ret == 0
                    {
                        return Err(Error::last_os_error());
                    }
                    else
                    {
                        return Ok(convert_to_string(process_path.as_mut_ptr()));
                    }
                }
        }

        // Close our handle...
        CloseHandle(snapshot);
    }

    Err(
        Error::new(
            ErrorKind::NotFound,
            "Steam process couldn't be found...",
        )
    )
}

/**
 * Finds the program files folder.
 */
fn find_documents() -> std::result::Result<String, Error>
{
    let mut max_path = [0i8; MAX_PATH];

    let ret = unsafe {
        SHGetSpecialFolderPathA(
            null_mut(),
            max_path.as_mut_ptr(),
            CSIDL_PERSONAL,
            TRUE,
        )
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
fn launch_steam(account: &Account, configuration: &Configuration) -> std::result::Result<i32, Error>
{
    // Setup our launch arguments...
    let shutdown_arguments = CString::new(format!("{} -shutdown", configuration.steam_path))
        .expect("Failed to convert CString...");

    let arguments = CString::new(format!("{} -login {} {}", configuration.steam_path, account.username, account.password))
        .expect("Failed to convert CString...");

    // Setup our startup information and process information.
    let mut si: STARTUPINFOA = unsafe { mem::zeroed() };
    let mut pi: PROCESS_INFORMATION = unsafe { mem::zeroed() };

    // Update the cb value.
    si.cb = mem::size_of::<STARTUPINFOA>() as u32;

    // Attempt to create the process...
    let ret = unsafe {
        while get_running_steam_process().is_ok()
        {
            println!("Waiting for Steam to close...");
            CreateProcessA(
                null_mut(),
                shutdown_arguments.as_ptr() as *mut i8,
                null_mut(),
                null_mut(),
                FALSE,
                0,
                null_mut(),
                null_mut(),
                &mut si,
                &mut pi,
            );

            std::thread::sleep(std::time::Duration::from_secs(1));
        }

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
            &mut pi,
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

fn first_time_setup() -> Configuration
{
    println!("Performing first time setup!");

    loop {
        let steam = get_running_steam_process();

        if steam.is_err()
        {
            println!("Please launch Steam for the initial setup!");
            std::thread::sleep(std::time::Duration::from_secs(1));

            continue;
        }

        let steam = steam.unwrap();

        ///////////////////////////////////////////

        println!("Located Steam! ({})", steam);

        let mut configuration: Configuration = Default::default();
        configuration.steam_path = steam;
        configuration.auto_close = true;

        ///////////////////////////////////////////

        return configuration;
    }
}

fn save_configuration(configuration: &Configuration) -> Result<(), Error>
{
    let documents_path = find_documents()?;
    let path = format!("{}{}", documents_path, CONFIGURATION_FILE_NAME);

    ///////////////////////////////////////

    let serialized = serde_json::to_string(&configuration)?;
    fs::write(&path, serialized)?;

    Ok(())
}

fn load_configuration() -> Result<Configuration, Error>
{
    let documents_path = find_documents()?;

    ///////////////////////////////////////

    let path = format!("{}{}", documents_path, CONFIGURATION_FILE_NAME);
    let read_file = fs::read_to_string(&path);

    // If first time setup...
    if read_file.is_err()
    {
        // Run our first time setup...
        let configuration = first_time_setup();

        ////////////////////////////////////////

        // Attempt to save our config...
        let save_config = save_configuration(&configuration);
        if save_config.is_err()
        {
            return Err(save_config.err().unwrap());
        }

        return Ok(configuration);
    }

    ///////////////////////////////////////

    let read_string = read_file.unwrap();
    let configuration = serde_json::from_str::<Configuration>(&read_string)?;

    return Ok(configuration);
}

fn help()
{
    println!("Help:");
    println!("----------------------------------");
    println!("Adding an account: a or add");
    println!("Delete an account: d or delete");
    println!("Toggle auto-close: k or autoclose");
    println!("Quit: q or quit");
    println!("----------------------------------");
}

fn list(configuration: &Configuration)
{
    // Check if there aren't any accounts...
    if configuration.accounts.len() == 0 { return; }

    // Separating line...
    println!("----------------------------------");

    // Iterate through all our accounts printing the index and nickname...
    for (i, account) in configuration.accounts.iter().enumerate()
    {
        println!("({}) {}", i, account.nickname);
    }

    // Separating line...
    println!("----------------------------------");
}

fn remove(configuration: &mut Configuration)
{
    ///////////////////////////////////////////

    // List our items...
    list(&configuration);

    // Ask for nickname...
    println!("Please choose an item to remove (:q to back):");
    let idx = get_input();

    // Check if a quit command was sent...
    if idx == ":q" { return; }

    let is_numeric = idx.parse::<usize>();

    if is_numeric.is_err()
    {
        println!("Invalid input!");
        return;
    }

    ////////////////////////////////////////

    let idx = is_numeric.unwrap();

    if idx > configuration.accounts.len()
    {
        println!("The account with the index of ({}) does not exist...", idx);
        return;
    }

    ////////////////////////////////////////

    // Push the account.
    configuration.accounts.remove(idx);

    // Attempt to save our config...
    save_configuration(&configuration);
}

fn toggle_auto_close(configuration: &mut Configuration)
{
    // Push the account.
    configuration.auto_close = !configuration.auto_close;

    // Inform user...
    println!("Auto-close was set to {}...", configuration.auto_close);

    // Attempt to save our config...
    save_configuration(&configuration);
}


fn add(configuration: &mut Configuration)
{
    ///////////////////////////////////////////

    // Ask for nickname...
    println!("Please choose a nickname (:q to back):");
    let nickname = get_input();

    // Check if a quit command was sent...
    if nickname == ":q" { return; }

    ///////////////////////////////////////////

    // Ask for username...
    println!("Please choose a username (:q to back):");
    let username = get_input();

    // Check if a quit command was sent...
    if username == ":q" { return; }

    ///////////////////////////////////////////

    // Ask for password...
    println!("Please choose a password (:q to back):");
    let password = get_input();

    // Check if a quit command was sent...
    if password == ":q" { return; }

    ////////////////////////////////////////

    // Setup our account.
    let account = Account { nickname, username, password };

    // Push the account.
    configuration.accounts.push(account);

    // Attempt to save our config...
    save_configuration(&configuration);
}

fn select(idx: usize, configuration: &Configuration)
{
    // Check if out of bounds...
    if idx > configuration.accounts.len()
    {
        println!("The account with the index of ({}) does not exist...", idx);
        return;
    }

    // Get our account...
    let account = configuration.accounts.get(idx).unwrap();

    // Launch our steam...
    let attempt = launch_steam(&account, &configuration);

    if attempt.is_err()
    {
        println!("Failed to launch Steam... {:?}", attempt.err());
    }

    // Inform user...
    println!("Launching Steam for user ({})...", account.nickname);

    // Auto-close if enabled...
    if configuration.auto_close { std::process::exit(0); }
}

fn get_input() -> String
{
    // Setup our input...
    let mut input = String::with_capacity(256);

    print!("> ");

    // Flush our stdout...
    io::stdout().flush();

    // Read our line...
    io::stdin().read_line(&mut input).unwrap();

    // Return our string which is also trimmed.
    String::from(input.trim())
}

fn start()
{
    // Get our configuration...
    let mut configuration = load_configuration();

    // Check if our configuration failed to load...
    if configuration.is_err()
    {
        println!("{:?}", configuration.err());
        io::stdin().read(&mut[0]).unwrap();
        return;
    }

    // Unwrap our configuration...
    let mut configuration = configuration.unwrap();

    // List all our accounts...
    list(&configuration);

    loop {
        let input = get_input();

        match input.as_str() {
            "help" | "h" => help(),
            "list" | "l" => list(&configuration),
            "delete" | "d" => remove(&mut configuration),
            "autoclose" | "k" => toggle_auto_close(&mut configuration),
            "add" | "a" => add(&mut configuration),
            "quit" | "q" => break,
            _ => {
                let is_numeric = input.parse::<usize>();

                match is_numeric {
                    Ok(idx) => select(idx, &configuration),
                    Err(e) => println!("Unknown command provided, use 'help' or 'h' to get more information..."),
                }
            },
        }
    }


}

fn main()
{
    start();
}
