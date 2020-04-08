// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"fmt"
	"math/big"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

// BlockValidator is responsible for validating block headers, uncles and
// processed state.
//
// BlockValidator implements Validator.
type BlockValidator struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for validating
}

// NewBlockValidator returns a new block validator which is safe for re-use
func NewBlockValidator(config *params.ChainConfig, blockchain *BlockChain, engine consensus.Engine) *BlockValidator {
	validator := &BlockValidator{
		config: config,
		engine: engine,
		bc:     blockchain,
	}
	return validator
}

// ValidateBody validates the given block's uncles and verifies the the block
// header's transaction and uncle roots. The headers are assumed to be already
// validated at this point.
func (v *BlockValidator) ValidateBody(block *types.Block) error {
	// Check whether the block's known, and if not, that it's linkable
	if v.bc.HasBlockAndState(block.Hash()) {
		return ErrKnownBlock
	}
	log.Info("Vote cast at block validator is", "data ",fmt.Sprintf("%x",block.VoteCastCall()))
	if !v.bc.HasBlockAndState(block.ParentHash()) {
		return consensus.ErrUnknownAncestor
	}
	// Header validity is known at this point, check the uncles and transactions
	header := block.Header()
	if err := v.engine.VerifyUncles(v.bc, block); err != nil {
		return err
	}
	if hash := types.CalcUncleHash(block.Uncles()); hash != header.UncleHash {
		return fmt.Errorf("uncle root hash mismatch: have %x, want %x", hash, header.UncleHash)
	}
	if hash := types.DeriveSha(block.Transactions()); hash != header.TxHash {
		return fmt.Errorf("transaction root hash mismatch: have %x, want %x", hash, header.TxHash)
	}
	return nil
}

// ValidateState validates the various changes that happen after a state
// transition, such as amount of used gas, the receipt roots and the state root
// itself. ValidateState returns a database batch if the validation was a success
// otherwise nil and an error is returned.
//
// For quorum it also verifies if the canonical hash in the blocks state points to a valid parent hash.
// For probablistic blockchain it compares the consensus decision value as well
func (v *BlockValidator) ValidateState(block, parent *types.Block, statedb *state.StateDB, receipts types.Receipts, usedGas *big.Int) error {
	header := block.Header()
	if block.GasUsed().Cmp(usedGas) != 0 {
		return fmt.Errorf("invalid gas used (remote: %v local: %v)", block.GasUsed(), usedGas)
	}
	// Validate the received block's bloom with the one derived from the generated receipts.
	// For valid blocks this should always validate to true.
	rbloom := types.CreateBloom(receipts)
	if rbloom != header.Bloom {
		return fmt.Errorf("invalid bloom (remote: %x  local: %x)", header.Bloom, rbloom)
	}
	// Tre receipt Trie's root (R = (Tr [[H1, R1], ... [Hn, R1]]))
	receiptSha := types.DeriveSha(receipts)
	if receiptSha != header.ReceiptHash {
		return fmt.Errorf("invalid receipt root hash (remote: %x local: %x)", header.ReceiptHash, receiptSha)
	}
	// Validate the state root against the received state root and throw
	// an error if they don't match.
	if root := statedb.IntermediateRoot(v.config.IsEIP158(header.Number)); header.Root != root {
		return fmt.Errorf("invalid merkle root (remote: %x local: %x)", header.Root, root)
	}
	//This code check the previous trransactions if there is a transaction with the same ID then it is added to the 	//transactions of the current block
	//First it collects the ID of the current transactions 
	var votes [][]*big.Int
	for _, n := range block.Transactions() {		
		if (n.ProbTran()){
			votes= append(votes,[]*big.Int{n.EventID(),n.Vote()})
	}
	}
	for _, n := range block.PreviousTrans() {		
		if (n.ProbTran()){
			votes= append(votes,[]*big.Int{n.EventID(),n.Vote()})
	}
	}
	var votesPerEvent [] Events
	votesPerEvent = ListEvents(votes)
	for i, _:= range votesPerEvent {
		if (Mean(votesPerEvent[i].votes).String()!=block.VoteCastCall()[i][3]){
			log.Info("Vote cast at block validator is", "data ",fmt.Sprintf("%x",block.VoteCastCall()[i][4]))
			return fmt.Errorf("invalid votecast mean")
		}
		if (StandardDeviation(votesPerEvent[i].votes).String()!=block.VoteCastCall()[i][5]){
			return fmt.Errorf("invalid votecast std")
		}
			
	}
	return nil
}

// CalcGasLimit computes the gas limit of the next block after parent.
// The result may be modified by the caller.
// This is miner strategy, not consensus protocol.
func CalcGasLimit(parent *types.Block) *big.Int {
	// contrib = (parentGasUsed * 3 / 2) / 4096
	contrib := new(big.Int).Mul(parent.GasUsed(), big.NewInt(3))
	contrib = contrib.Div(contrib, big.NewInt(2))
	contrib = contrib.Div(contrib, params.GasLimitBoundDivisor)

	// decay = parentGasLimit / 4096 - 1
	decay := new(big.Int).Div(parent.GasLimit(), params.GasLimitBoundDivisor)
	decay.Sub(decay, big.NewInt(1))

	/*
		strategy: gasLimit of block-to-mine is set based on parent's
		gasUsed value.  if parentGasUsed > parentGasLimit * (2/3) then we
		increase it, otherwise lower it (or leave it unchanged if it's right
		at that usage) the amount increased/decreased depends on how far away
		from parentGasLimit * (2/3) parentGasUsed is.
	*/
	gl := new(big.Int).Sub(parent.GasLimit(), decay)
	gl = gl.Add(gl, contrib)
	gl.Set(math.BigMax(gl, params.MinGasLimit))

	// however, if we're now below the target (TargetGasLimit) we increase the
	// limit as much as we can (parentGasLimit / 4096 -1)
	if gl.Cmp(params.TargetGasLimit) < 0 {
		gl.Add(parent.GasLimit(), decay)
		gl.Set(math.BigMin(gl, params.TargetGasLimit))
	}
	return gl
}
// Mean returns the mean of an integer array as a float
func Mean(nums [] *big.Int) (mean *big.Int) {
	if len(nums) == 0 {
		return big.NewInt(0)
	}

	mean = new(big.Int)
	for _, n := range nums {
		mean = new(big.Int).Add(mean,n)
	}
	return (new(big.Int).Quo(mean,new(big.Int).SetInt64(int64(len(nums)))))
}

func StandardDeviation(nums [] *big.Int) (dev *big.Int) {
	if len(nums) == 0 {
		return big.NewInt(0)
	}

	m := Mean(nums)
	dev = new(big.Int)
	for _, n := range nums {
	//	dev += (new(big.Float).SetInt(big.NewInt(n)) - m) * ( new(big.Float).SetInt(big.NewInt(n)) - m)
		dev= new(big.Int).Add(new(big.Int).Mul(new(big.Int).Sub( n,m), new(big.Int).Sub( n,m)),dev)
	}
	dev = new(big.Int).Quo(dev,new(big.Int).SetInt64(int64(len(nums))))
	dev = new(big.Int).Sqrt(dev)//bigfloat.Pow(dev,new(big.Float).SetFloat64(0.5)) //math.Pow(dev/  big.Float(len(nums)), 0.5)
	return dev
}
func NormalConfidenceInterval(nums [] *big.Int) (lower *big.Int, upper *big.Int) {
	if len(nums) == 0 {
		return big.NewInt(0),big.NewInt(0)
	}

	conf := 1.95996 // 95% confidence for the mean, http://bit.ly/Mm05eZ
	mean := Mean(nums)
	dev := new(big.Int).Quo(StandardDeviation(nums),new(big.Int).Sqrt(big.NewInt(int64(len(nums)))))
	lower = new(big.Int).Sub(mean,new(big.Int).Mul(dev,big.NewInt(int64(conf))))
	upper = new(big.Int).Add(mean,new(big.Int).Mul(dev,big.NewInt(int64(conf))))
	return lower,upper
}
//function constains check if an int is in a list 
func contains(s [] *big.Int, e *big.Int) bool {
    for _, a := range s {
        if (a.Cmp(e)==0) {
            return true
        }
    }
    return false
}
type Events struct {
	id *big.Int  
	votes [] *big.Int
}
// ListEvents function take all decisions and return the list of events included 
func ListEvents ( votes [][] *big.Int) []Events {
	var ids [] *big.Int
	var events [] Events
	 
	for m,_:=range votes{ 
		if (! contains(ids, votes[m][0])) {
			ids= append(ids, votes[m][0])
			var e Events
			e.id= votes[m][0]
			e.votes= append(e.votes,votes[m][1])
			events= append(events,e)
			
		} else {
		 for i,event := range events{
		 	if (event.id.Cmp(votes[m][0])==0) {
				event.votes= append(event.votes,votes[m][1])
				events[i]=event
				
				}}
		}}
	return events
}
