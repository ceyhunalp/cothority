package tournament

//func init() {
//	var err error
//	err = byzcoin.RegisterGlobalContract(ContractTournamentID,
//		contractTournamentFromBytes)
//	if err != nil {
//		log.ErrFatal(err)
//	}
//}

type KeyValue struct {
	Key   string
	Value []byte
}

// KeyValueData is the structure that will hold all key/value pairs.
type KeyValueData struct {
	Storage []KeyValue
}
