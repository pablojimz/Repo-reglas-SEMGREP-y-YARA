let log_message_vulnerable username message =
  Printf.printf "User: %s - Message: %s\n" username message

let log_error_vulnerable error_code user_input =
  Printf.eprintf "Error %d: %s\n" error_code user_input