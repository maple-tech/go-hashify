//Package hashify performs hashing functionality on arbitrary structs.
//Will hash any value really, but is intended for structs and the likes.
//Structs can use the field tag "hash" to declare a different keying
//name for the field other then the one provided, alternatively if the
//value '-' is provided, then the field will be skipped in the hashing process.
package hashify
