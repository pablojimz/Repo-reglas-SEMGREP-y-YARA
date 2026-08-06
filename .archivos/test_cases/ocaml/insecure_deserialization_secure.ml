type data = { value : int }

let () =
  let trusted_data = Marshal.to_string { value = 123 } [] in
  let obj = Marshal.from_string trusted_data 0 in
  (match obj with
  | {value} -> Printf.printf "Deserialized trusted data: %d\n" value
  | _ -> Printf.printf "Error: Unexpected data type\n")