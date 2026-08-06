type user = { name : string; id : int }

let () =
  let filename = "malicious_data.bin" in
  let ic = open_in_bin filename in
  try
    let obj = Marshal.from_channel ic in
    (match obj with
    | {name; id} -> Printf.printf "Deserialized user: %s (ID: %d)\n" name id
    | _ -> Printf.printf "Deserialized unknown type\n");
    close_in ic
  with e ->
    close_in_noerr ic;
    Printf.eprintf "Error during deserialization: %s\n" (Printexc.to_string e)