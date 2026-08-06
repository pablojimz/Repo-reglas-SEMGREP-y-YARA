let () =
  print_string "Enter command: ";
  let user_input = read_line () in
  Sys.command user_input |> ignore;
  print_string "Command executed.\n"