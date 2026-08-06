(* Assuming a stronger cryptographic library is available, e.g., using ocaml-cryptokit for SHA256 *)
(* For password hashing, a library like bcrypt or Argon2 should be used *)

let hash_password_secure password =
  (* Example using a hypothetical strong hash function *)
  Cryptokit.Hash.sha256 (password)

let hash_data_secure data =
  Cryptokit.Hash.sha256 (data)
