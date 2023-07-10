use std::collections::HashMap;

pub fn parse_string(s: &str) -> HashMap<&str, &str> {
    let mut map: HashMap<&str, &str> = HashMap::default();
    s.split("&").for_each(|split| {
        let kv: Vec<&str> = split.split("=").collect();
        if kv.len() == 2 {
            map.insert(kv[0], kv[1]);
        }
    });

    map
}

pub fn encode_string(map: HashMap<&str, String>) -> String {
    map.into_iter()
        .map(|(key, value)| return format!("{}={}", key, value))
        .collect::<Vec<String>>()
        .join("&")
}

pub fn profile_for(email: &str) -> String {
    let sanitized = email.replace("&", "").replace("=", "");

    let a = [
        ("email", sanitized),
        ("uid", "10".to_string()),
        ("role", "user".to_string()),
    ]
    .map(|(key, value)| return format!("{}={}", key, value))
    .join("&");

    return a;
}
