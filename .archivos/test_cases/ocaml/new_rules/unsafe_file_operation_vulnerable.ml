let read_file_unsafe filename =
  let ic = open_in filename in
  let line = input_line ic in
  close_in ic;
  line

let create_file_unsafe filename content =
  let oc = open_out filename in
  output_string oc content;
  close_out oc