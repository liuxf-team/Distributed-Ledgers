use node::config::config::Config;
use node::node::Node;
pub fn main(){   

    let gs_tbk_config_path  = String::from(std::env::current_dir().unwrap().as_path().to_str().unwrap())+"/node/src/config/config_files/gs_tbk_config.json";
    let gs_tbk_config:Config = serde_json::from_str(&Config::load_config(&gs_tbk_config_path)).unwrap();
    //println!("666");

    let node = Node::init(gs_tbk_config);
    println!("{:?}",node);

}

#[test]
fn test()
{
    
}