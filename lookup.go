package lookup

func makeName(name string, prefix string) {

	if prefix == "" {
		return name
	} else {

	}

}

func doLookup(f *lookup.LookupFactory, gc *conf.GlobalConf, input <-chan string, output chan<- string) error {

	for n := range in input {
		lookupName = makeName(rawName, gc.NamePrefix)
		l, err := f.MakeLookup()
		if err {

		}
		res, err := f.DoLookup(lookupName)
	}
}

// write results from lookup to output file
func output(out <-chan string, path string) error {
	var f *File;
	if path == "" || path == "-" {
		f = os.Stdout
	} else {
		f, err := os.Open(path)
	}
	for n := range in out {
		f.

	}
}

// read input file and put results into channel
func input(in chan<- string, path string, bool ) error {

}



func DoLookups(f *lookup.LookupFactory, c *conf.GlobalConf) error {

	c := make(chan int)

}
