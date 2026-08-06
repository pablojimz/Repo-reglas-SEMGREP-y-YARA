let () =
  Sys.command "ls -l /tmp" |> ignore;
  print_string "Safe command executed.\n"