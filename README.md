# go-hashify
Generates hashes from given arbitrary structs for checksum or other identification purposes.

## Usage
To generate a hash, a couple different functions are provided, they all mostly do the same thing.
At the moment, the `crypto/SHA1` and `crypto/MD5` hashes are available, but you can use your own if it implements
`hash.Hash`.

To generate a basic hexidecimal string of a SHA1 hashed struct:
```go
type SomeStruct struct {
    Str string
    Num int64
    Map map[string]float32
    NotHashed bool `hash:"-"`      //<- Not included for hashing
    Renamed bool `hash:"original"` //<- For backwards compat with other structs
}
val := SomeStruct{ ... }
hash, err := hashify.SHA1String(val)
fmt.Println(hash)
```

To customize the way an object get's hashed, you can implement the `hashify.Hashable` interface
by providing the `func Hash(io.Writer)error` method. From here you can write any byte representation
needed for the hasher.

Note, with reflection only exported fields using the interface will be written.

```go
type Custom struct {
	Str string
}

func (c Custom) Hash(w io.Writer) error {
	w.Write([]byte(strings.ToUpper(c.Str)))
	return nil
}
```