package hashify

import (
	"io"
	"reflect"
)

//Hashable interface for types that want to implement a custom
//function for writing the data to the hashing function.
type Hashable interface {

	//Hash allows a type to perform it's own data writing for
	//the hashing function. Should return an error if something
	//goes wrong, which will be propogated up through the
	//hashify functions
	Hash(io.Writer) error
}

var hashableInterface = reflect.TypeOf((*Hashable)(nil)).Elem()
