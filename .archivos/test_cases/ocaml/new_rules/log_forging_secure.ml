let sanitize_log_input input =
  String.map (function
    | '\n' -> ' '
    | '\r' -> ' '
    | c -> c
  ) input

let log_message_secure username message =
  let sanitized_username = sanitize_log_input username in
  let sanitized_message = sanitize_log_input message in
  Printf.printf "User: %s - Message: %s\n" sanitized_username sanitized_message

let log_error_secure error_code user_input =
  let sanitized_input = sanitize_log_input user_input in
  Printf.eprintf "Error %d: %s\n" error_code sanitized_input