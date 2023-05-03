package tournament

import (
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

func init() {
	var err error
	_, err = onet.RegisterNewService("tournamentLottery", newService)
	if err != nil {
		log.ErrFatal(err)
	}
	err = byzcoin.RegisterGlobalContract(ContractTournamentID, contractTournamentFromBytes)
	if err != nil {
		log.ErrFatal(err)
	}
}

type Service struct {
	*onet.ServiceProcessor
}

func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	return s, nil
}
