use std::collections::HashMap;
use tokio::net::{TcpStream};

use regulator::regulator::Regulator;
use regulator::config::config::Config;

pub fn main()
{
// Init and build communication

// Setup phase
    // maintain communication
    let mut communication_map:HashMap<u16, TcpStream> = HashMap::new();
    let gs_tbk_config_path  = String::from(std::env::current_dir().unwrap().as_path().to_str().unwrap())+"/regulator/src/config/config_files/gs_tbk_config.json";
    let gs_tbk_config:Config = serde_json::from_str(&Config::load_config(&gs_tbk_config_path)).unwrap();
    let regulator = Regulator::init(gs_tbk_config);
    println!("{:?}",regulator);

}

#[test]
fn test_load_config() 
{
    println!("{:?}",std::env::current_dir().unwrap().as_path().to_str().unwrap().to_owned()+"/src/config/config_files/gs_tbk_config.json");
    let gs_tbk_config_path  = String::from(std::env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/config/config_files/gs_tbk_config.json";
    println!("{:?}",Config::load_config(&gs_tbk_config_path));
    
}