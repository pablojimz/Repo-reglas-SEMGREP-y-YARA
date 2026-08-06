let is_safe_filename filename =
  not (String.contains filename '/') && not (String.contains filename '\\')

let read_file_safe filename =
  if not (is_safe_filename filename) then
    failwith "Invalid filename"
  else
    let ic = open_in (Filename.concat "./safe_dir" filename) in
    let line = input_line ic in
    close_in ic;
    line

let create_file_safe filename content =
  if not (is_safe_filename filename) then
    failwith "Invalid filename"
  else
    let oc = open_out (Filename.concat "./safe_dir" filename) in
    output_string oc content;
    close_out oc