package worker

import (
	"errors"
	"github.com/fadhilkurnia/shamir/csprng"
	"github.com/fadhilkurnia/shamir/krawczyk"
	"github.com/fadhilkurnia/shamir/shamir"
)

const AlgShamir = "shamir"
const AlgSSMS = "krawczyk"

// Worker is a secret-sharing worker with a single randomization source
type Worker struct {
	r *csprng.CSPRNG
}

func NewWorker() Worker {
	return Worker{
		csprng.NewCSPRNG(),
	}
}

func (w *Worker) Split(algorithm string, input []byte, n, k int) ([][]byte, error) {
	if algorithm != AlgShamir && algorithm != AlgSSMS {
		return nil, errors.New("invalid secret-sharing algorithm")
	}
	if algorithm == AlgShamir {
		return shamir.SplitWithRandomizer(input, n, k, w.r)
	}
	return krawczyk.SplitWithRandomizer(input, n, k, w.r)
}

func (w *Worker) Combine(algorithm string, secretSharedData [][]byte, n, k int) ([]byte, error){
	if algorithm != AlgShamir && algorithm != AlgSSMS {
		return nil, errors.New("invalid secret-sharing algorithm")
	}
	if algorithm == AlgShamir {
		return shamir.Combine(secretSharedData)
	}
	return krawczyk.Combine(secretSharedData, n, k)
}