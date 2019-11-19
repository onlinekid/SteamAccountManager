#[cfg(windows)]
extern crate winapi;

use std::io::{Error, Read, Write};
use std::{fs, io};
use serde::{Serialize, Deserialize};

macro_rules! save {
    ($name:expr) => {
        match save_configuration(&$name) {
            Ok(_) => { },
            Err(_) => { println!("Failed to save configuration! Check write permissions!") },
        };
    }
}


#[cfg(target_os = "macos")]
use libproc::libproc::proc_pid;

#[cfg(target_os = "macos")]
use std::io::ErrorKind;

#[cfg(target_os = "macos")]
use libproc::libproc::proc_pid::ProcType;

#[cfg(windows)]
use std::ffi::{OsStr, OsString};
#[cfg(windows)]
use std::os::windows::ffi::{OsStrExt, OsStringExt};
#[cfg(windows)]
use std::ptr::{null_mut};
#[cfg(windows)]
use std::mem;

#[cfg(windows)]
use winapi::um::processthreadsapi::{CreateProcessW, OpenProcess, PROCESS_INFORMATION, STARTUPINFOW};
#[cfg(windows)]
use winapi::um::shlobj::{SHGetSpecialFolderPathW, CSIDL_PERSONAL};
#[cfg(windows)]
use winapi::shared::minwindef::{FALSE, MAX_PATH, TRUE};
#[cfg(windows)]
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
#[cfg(windows)]
use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
#[cfg(windows)]
use winapi::um::psapi::{GetModuleFileNameExW};
#[cfg(windows)]
use winapi::shared::ntdef::{HANDLE};
#[cfg(windows)]
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

#[allow(dead_code)]
#[derive(Default)]
struct SteamProcess
{
    steam_path: String,
    pid: u32
}

#[cfg(target_os = "macos")]
const CONFIGURATION_FILE_NAME: &str = "steam_account_manager.cfg";

#[cfg(target_os = "windows")]
const CONFIGURATION_FILE_NAME: &str = "\\steam_account_manager.cfg";

#[cfg(target_os = "windows")]
fn wide_string_to_string(input: &[u16]) -> String
{
    let len = input.iter().take_while(|&&c| c != 0).count();

    let os: OsString = OsStringExt::from_wide(&input[..len]);
    os.into_string().unwrap()
}

#[cfg(target_os = "windows")]
fn string_to_wide_string(input: String) -> Vec<u16>
{
    let input = OsStr::new(&input);
    let vec: Vec<u16> = input.encode_wide().chain(Some(0)).collect();
    vec
}

#[cfg(target_os = "macos")]
fn get_running_steam_process() -> std::result::Result<SteamProcess, Error>
{
    // Attempt to find all pids...
    let pids = proc_pid::listpids(ProcType::ProcAllPIDS);

    if pids.is_err()
    {
        return Err(
            Error::new(
                ErrorKind::NotFound,
                "Failed to fetch all running processes...",
            )
        );
    }

    // Iterate throughout all our pids...
    for pid in pids.unwrap() {
        let process_name = proc_pid::name(pid as i32);
        let process_path = proc_pid::pidpath(pid as i32);

        if process_name.is_err() || process_path.is_err() { continue; }

        let process_name = process_name.unwrap();
        let process_path = process_path.unwrap();

        // Attempt to find steam_osx...
        if process_name == "steam_osx"
        {
            // Parse and format Steam's path...
            let process_path = process_path.replace("Contents/MacOS/steam_osx", "Contents/MacOS/Steam.app/Contents/MacOS/steam_osx");

            // Return Steam's process path.
            return Ok(SteamProcess {
                steam_path: process_path,
                pid
            });
        }
    }

    Err(
        Error::new(
            ErrorKind::NotFound,
            "Steam process couldn't be found...",
        )
    )
}

#[cfg(windows)]
fn get_running_steam_process() -> std::result::Result<SteamProcess, Error>
{
    // Setup our process entry struct with the correct size...
    let mut entry: PROCESSENTRY32W = unsafe { mem::zeroed() };
    entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;

    unsafe {
        // Get our snapshot...
        let snapshot: HANDLE = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        let mut should_loop = Process32FirstW(snapshot, &mut entry) == TRUE;

        // Enumerate through all our processes...
        while should_loop {
            // Get our process name...
            let process_name = wide_string_to_string(entry.szExeFile.as_ref());

            // Continue the loop if it is not Steam...
            if process_name != "Steam.exe"
            {
                should_loop = Process32NextW(snapshot, &mut entry) == TRUE;
                continue;
            }

            ////////////////////////////////////

            // Attempt to open our process for query...
            let process_handle = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE,
                entry.th32ProcessID,
            );

            // Check if null...
            if process_handle.is_null()
            {
                should_loop = Process32NextW(snapshot, &mut entry) == TRUE;
                continue;
            }

            ////////////////////////////////////

            // Setup our process path with MAX_PATH (wrong)...
            let mut process_path = [0u16; MAX_PATH];

            // Get our module file name...
            let ret = GetModuleFileNameExW(
                process_handle,
                null_mut(),
                process_path.as_mut_ptr(),
                MAX_PATH as u32,
            );

            // Clean up.
            CloseHandle(process_handle);
            CloseHandle(snapshot);

            match ret {
                0 => return Err(Error::last_os_error()),
                _ => return Ok(SteamProcess {
                    steam_path: wide_string_to_string(process_path.as_ref()),
                    pid: entry.th32ProcessID
                })
            }
        }

        CloseHandle(snapshot);
    }

    Err(Error::last_os_error())
}

#[cfg(target_os = "macos")]
fn find_documents() -> std::result::Result<String, Error>
{
    Ok(String::from(""))
}

#[cfg(windows)]
fn find_documents() -> std::result::Result<String, Error>
{
    let mut max_path = [0u16; MAX_PATH];

    let ret = unsafe {
        SHGetSpecialFolderPathW(
            null_mut(),
            max_path.as_mut_ptr(),
            CSIDL_PERSONAL,
            TRUE,
        )
    };

    match ret {
        0 => return Err(Error::last_os_error()),
        _ => return Ok(wide_string_to_string(max_path.as_ref()))
    }
}

#[cfg(target_os = "macos")]
fn launch_steam(account: &Account, configuration: &Configuration) -> std::result::Result<(), Error>
{
    loop {
        let steam = get_running_steam_process();

        if steam.is_err() { break; }

        println!("Waiting for Steam to close...");

        let kill = std::process::Command::new("kill")
            .args(&["-9", format!("{}", steam.unwrap().pid).as_str()])
            .output();

        if kill.is_err()
        {
            return Err(
                Error::new(
                    ErrorKind::NotFound,
                    "Failed to close Steam...",
                )
            );
        }
    }

    let launch = std::process::Command::new(&configuration.steam_path)
        .args(&["-login", account.username.as_str(), account.password.as_str()])
        .output();

    if launch.is_err()
    {
        return Err(
            Error::new(
                ErrorKind::NotFound,
                "Failed to launch Steam...",
            )
        );
    }

    Ok(())
}

#[cfg(windows)]
fn launch_steam(account: &Account, configuration: &Configuration) -> std::result::Result<(), Error>
{
    // Wrapper for CreateProcessA.
    let create_process = |arguments: &mut Vec<u16>| -> std::result::Result<(), Error> {
        // Setup our startup information and process information.
        let mut si: STARTUPINFOW = unsafe { mem::zeroed() };
        let mut pi: PROCESS_INFORMATION = unsafe { mem::zeroed() };

        // Update the cb value.
        si.cb = mem::size_of::<STARTUPINFOW>() as u32;

        // Attempt to create the process...
        let ret = unsafe {
            CreateProcessW(
                null_mut(),
                arguments.as_mut_ptr(),
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

        match ret {
            0 => return Err(Error::last_os_error()),
            _ => return {
                // Clean up handles...
                unsafe {
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                }

                Ok(())
            }
        }
    };

    // Setup our launch arguments...
    let mut shutdown_arguments = string_to_wide_string(format!("\"{}\" -shutdown", configuration.steam_path));
    let mut arguments = string_to_wide_string(format!("\"{}\" -login {} {}", configuration.steam_path, account.username, account.password));

    // Resize to correct size.
    shutdown_arguments.resize(MAX_PATH, 0u16);
    arguments.resize(MAX_PATH, 0u16);

    // Loop until Steam is closed.
    while get_running_steam_process().is_ok() {
        println!("Waiting for Steam to close...");

        // Attempt to call Steam with the shutdown argument.
        create_process(&mut shutdown_arguments)?;

        // Sleep for one second.
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    create_process(&mut arguments)
}

fn first_time_setup(configuration: Option<&mut Configuration>) -> Result<Option<Configuration>, Error>
{
    if configuration.is_none()
    {
        println!("Performing first time setup!");
    }

    loop {
        // Get our running steam process.
        let steam = match get_running_steam_process() {
            Ok(steam) => steam,
            Err(_) => {
                println!("Please launch Steam for the initial setup!");
                std::thread::sleep(std::time::Duration::from_secs(1));

                continue;
            },
        };

        ///////////////////////////////////////////

        #[cfg(target_os = "macos")] {
            // We need to adjust the path and unzip our bootstrapper...
            let steam_mac_bootstrapper = steam.steam_path.replace("/Steam.app/Contents/MacOS/steam_osx", "/SteamMacBootstrapper.tar.gz");
            let steam_mac_bootstrapper_path = steam_mac_bootstrapper.replace("/SteamMacBootstrapper.tar.gz", "/");

            println!("Performing additional steps...");

            // Untar our tar...
            let launch = std::process::Command::new("tar")
                .args(&["xf", steam_mac_bootstrapper.as_str(), "-C", steam_mac_bootstrapper_path.as_str()])
                .output();

            if launch.is_err()
            {
                return Err(
                    Error::new(
                        ErrorKind::NotFound,
                        "Failed to process SteamMacBootstrapper...",
                    )
                );
            }
        }

        ///////////////////////////////////////////

        println!("Located Steam! ({})", steam.steam_path);

        // Handle our configuration.
        match configuration {
            None => {
                let mut configuration: Configuration = Default::default();
                configuration.steam_path = steam.steam_path;
                configuration.auto_close = true;

                return Ok(Some(configuration));
            },
            Some(configuration) => {
                // Inform user.
                println!("Updating Steam path configuration... ({})", steam.steam_path);

                // Update configuration.
                configuration.steam_path = steam.steam_path;

                // Save it.
                save!(configuration);

                // Return nothing...
                return Ok(Option::None);
            },
        }

        ///////////////////////////////////////////
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
        let configuration = first_time_setup(Option::None)?;
        let configuration = configuration.unwrap();

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


fn list(configuration: &Configuration)
{
    // Check if there aren't any accounts...
    if configuration.accounts.is_empty() { return; }

    // Separating line...
    println!("┌─────────────────────────────────────┐");

    // Iterate through all our accounts printing the index and nickname...
    for (i, account) in configuration.accounts.iter().enumerate() {
        println!("({}) {}", i, account.nickname);
    }

    // Separating line...
    println!("└─────────────────────────────────────┘");
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

    let idx = match idx.parse::<usize>() {
        Ok(idx) => idx,
        Err(_) => {
            println!("Invalid input!");
            return;
        },
    };

    /////////////////////////////////////////

    if idx >= configuration.accounts.len()
    {
        println!("The account with the index of ({}) does not exist...", idx);
        return;
    }

    ////////////////////////////////////////

    // Push the account.
    configuration.accounts.remove(idx);

    // Attempt to save our config...
    save!(configuration);
}

fn toggle_auto_close(configuration: &mut Configuration)
{
    // Push the account.
    configuration.auto_close = !configuration.auto_close;

    // Inform user...
    println!("Auto-close was set to {}...", configuration.auto_close);

    // Attempt to save our config...
    save!(configuration);
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
    save!(configuration);
}

fn select(idx: usize, configuration: &Configuration)
{
    // Check if out of bounds...
    if idx >= configuration.accounts.len()
    {
        println!("The account with the index of ({}) does not exist...", idx);
        return;
    }

    // Get our account...
    let account = configuration.accounts.get(idx).unwrap();

    // Inform user...
    println!("Launching Steam for user ({})...", account.nickname);

    // Launch our steam...
    let attempt = launch_steam(&account, &configuration);

    // Match our attempt
    match attempt {
        Ok(_) => {
            if configuration.auto_close { std::process::exit(0); }
        },
        Err(_) => {
            println!("Failed to launch Steam...");
        },
    }
}

fn get_input() -> String
{
    // Setup our input...
    let mut input = String::with_capacity(256);

    print!("> ");

    // Flush our stdout...
    io::stdout().flush().unwrap();

    // Read our line...
    io::stdin().read_line(&mut input).unwrap();

    // Return our string which is also trimmed.
    String::from(input.trim())
}

fn help()
{
    println!("┌─ Help ─────────────────────────────┐");
    println!("(a or add): Adding an account");
    println!("(d or delete): Delete an account");
    println!("(k or autoclose): Toggle auto-close");
    println!("(r or retarget): Retarget Steams path (use if changed computers)");
    println!("(q or quit): Quit");
    println!("└─────────────────────────────────────┘");
}

fn retarget(configuration: &mut Configuration)
{
    match first_time_setup(Option::Some(configuration)) {
        Ok(_) => println!("Successfully retarget configuration!"),
        Err(_) => println!("Failed to retarget configuration!"),
    }
}

fn start()
{
    // Get our configuration...
    let configuration = load_configuration();

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

    // Perform an infinite loop.
    loop {
        // Get input.
        let input = get_input();

        // Match our command.
        match input.as_str() {
            "help" | "h" => help(),
            "list" | "l" => list(&configuration),
            "delete" | "d" => remove(&mut configuration),
            "autoclose" | "k" => toggle_auto_close(&mut configuration),
            "retarget" | "r" => retarget(&mut configuration),
            "add" | "a" => add(&mut configuration),
            "quit" | "q" => break,
            _ => {
                let is_numeric = input.parse::<usize>();

                match is_numeric {
                    Ok(idx) => select(idx, &configuration),
                    Err(_) => println!("Unknown command provided, use 'help' or 'h' to get more information..."),
                }
            },
        }
    }
}

fn main()
{
    start();
}