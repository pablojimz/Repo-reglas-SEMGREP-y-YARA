let divide_safe x y =
  try
    x / y
  with
  | Division_by_zero ->
      Printf.eprintf "Error: Invalid operation.\n";
      -1

let () =
  let result = divide_safe 10 0 in
  Printf.printf "Safe result: %d\n" result