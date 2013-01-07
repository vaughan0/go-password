go-password
===========

Simple Go package for working with cryptographically-secure password hashes.

Usage
-----

Generate a hash from a password:

    import "github.com/vaughan0/go-password"
    hash := password.Hash("superdupersecret")

Check user input against the hash:

    if password.Check("password", hash) {
      fmt.Println("Correct! (ps. you need a better password)")
    } else {
      fmt.Println("Wrong password")
    }

Setting the hash algorithm
--------------------------

go-password supports the md5, sha256, sha1 and bcrypt hashing algorithms, and
by default uses bcrypt with a cost of 8. To customize the algorithm used, first create
a new Manager and then change it's Default field:

		manager := password.New()
    manager.Default = "sha256"

		hash := manager.Hash("password")
		// hash => "sha256$blahblahblah"

If you want to change the cost of the bcrypt algorithm on a per-Manager basis,
register a new Bcrypt instance with the manager:

    manager.Register("bcrypt", password.Bcrypt{customCost})

Custom hash algorithms
----------------------

If you want to use a custom hash algorithm with go-password, you need to
implement the Algorithm interface:

    type Algorithm interface {
      Hash(password []byte) []byte
      Check(password, hashed []byte) bool
    }

Then register your algorithm:

    var algorithm password.Algorithm = new(MyAlgorithm)
    password.Register("myhash", algorithm)

Alternatively, if you just want to register a hash that already provides a
hash.Hash implementation (from the standard hash package), you may use the
RegisterHash function. This also adds random salts to your hashes:

    var algorithm hash.Hash = myhashpackage.New()
    password.RegisterHash("myhash", algorithm)

Hash strings explained
----------------------

Example:

    bcrypt$JDJhJDA4JFZnVjNwLmI4cks4SGk0cHBPMWFGOWU1NVRXYjhCSmNVLlJUZVVBbTZZN0FLOEZnY2IwR0NL

The hash strings generated by go-password are made up of the hash algorithm's
name as it was registered (eg. "bcrypt" or "sha256"), followed by a dollar sign
($), followed by an encoded form of the algorithm-specific binary data. By
default the data is encoded with base64, but this can be changed by setting the
Manager.Codec field.
