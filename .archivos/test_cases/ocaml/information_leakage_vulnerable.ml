let divide x y =
  try
    x / y
  with
  | Division_by_zero ->
      Printf.eprintf "Error: Division by zero occurred. Backtrace:\n";
      Printexc.print_backtrace stderr;
      -1

let () =
  let result = divide 10 0 in
  Printf.printf "Result: %d\n" result