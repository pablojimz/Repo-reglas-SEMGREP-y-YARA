let api_key = Sys.getenv "API_KEY"
let password = read_password_from_config ()
let token = get_token_from_vault ()
let secret_var = "thisisnotasecret"