#[cfg(windows)]
mod windows;

#[cfg(windows)]
fn main()
{
    windows::start();
}

#[cfg(macos)]
fn main()
{
    println!("This program only runs on Windows.")
}