let hash_password_md5 password =
  Digest.string password

let hash_data_sha1 data =
  Sha1.hash data