// Copyright 2014 The go-ethereum Authors
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

// Package types contains data types related to Ethereum consensus.
package types

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"sort"
	"sync/atomic"
	"time"
	"github.com/ethereum/go-ethereum/log"
	//"github.com/bigfloat"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/ethereum/go-ethereum/rlp"
)

var (
	EmptyRootHash  = DeriveSha(Transactions{})
	EmptyUncleHash = CalcUncleHash(nil)
)

// A BlockNonce is a 64-bit hash which proves (combined with the
// mix-hash) that a sufficient amount of computation has been carried
// out on a block.
type BlockNonce [8]byte

// EncodeNonce converts the given integer to a block nonce.
func EncodeNonce(i uint64) BlockNonce {
	var n BlockNonce
	binary.BigEndian.PutUint64(n[:], i)
	return n
}

// Uint64 returns the integer value of a block nonce.
func (n BlockNonce) Uint64() uint64 {
	return binary.BigEndian.Uint64(n[:])
}

// MarshalText encodes n as a hex string with 0x prefix.
func (n BlockNonce) MarshalText() ([]byte, error) {
	return hexutil.Bytes(n[:]).MarshalText()
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (n *BlockNonce) UnmarshalText(input []byte) error {
	return hexutil.UnmarshalFixedText("BlockNonce", input, n[:])
}

//go:generate gencodec -type Header -field-override headerMarshaling -out gen_header_json.go

// Header represents a block header in the Ethereum blockchain.
type Header struct {
	ParentHash  common.Hash    `json:"parentHash"       gencodec:"required"`
	UncleHash   common.Hash    `json:"sha3Uncles"       gencodec:"required"`
	Coinbase    common.Address `json:"miner"            gencodec:"required"`
	Root        common.Hash    `json:"stateRoot"        gencodec:"required"`
	TxHash      common.Hash    `json:"transactionsRoot" gencodec:"required"`
	ReceiptHash common.Hash    `json:"receiptsRoot"     gencodec:"required"`
	Bloom       Bloom          `json:"logsBloom"        gencodec:"required"`
	Difficulty  *big.Int       `json:"difficulty"       gencodec:"required"`
	Number      *big.Int       `json:"number"           gencodec:"required"`
	GasLimit    *big.Int       `json:"gasLimit"         gencodec:"required"`
	GasUsed     *big.Int       `json:"gasUsed"          gencodec:"required"`
	Time        *big.Int       `json:"timestamp"        gencodec:"required"`
	Extra       []byte         `json:"extraData"        gencodec:"required"`
	MixDigest   common.Hash    `json:"mixHash"          gencodec:"required"`
	Nonce       BlockNonce     `json:"nonce"            gencodec:"required"`
}

// field type overrides for gencodec
type headerMarshaling struct {
	Difficulty *hexutil.Big
	Number     *hexutil.Big
	GasLimit   *hexutil.Big
	GasUsed    *hexutil.Big
	Time       *hexutil.Big
	Extra      hexutil.Bytes
	Hash       common.Hash `json:"hash"` // adds call to Hash() in MarshalJSON
}

// Hash returns the block hash of the header, which is simply the keccak256 hash of its
// RLP encoding.
func (h *Header) Hash() common.Hash {
	return rlpHash(h)
}

// HashNoNonce returns the hash which is used as input for the proof-of-work search.
func (h *Header) HashNoNonce() common.Hash {
	return rlpHash([]interface{}{
		h.ParentHash,
		h.UncleHash,
		h.Coinbase,
		h.Root,
		h.TxHash,
		h.ReceiptHash,
		h.Bloom,
		h.Difficulty,
		h.Number,
		h.GasLimit,
		h.GasUsed,
		h.Time,
		h.Extra,
	})
}

func rlpHash(x interface{}) (h common.Hash) {
	hw := sha3.NewKeccak256()
	rlp.Encode(hw, x)
	hw.Sum(h[:0])
	return h
}

// Body is a simple (mutable, non-safe) data container for storing and moving
// a block's data contents (transactions and uncles) together.
type Body struct {
	Transactions []*Transaction
	Uncles       []*Header
	VoteCast     [][]string
	Previoustransactions []*Transaction
}

// Block represents an entire block in the Ethereum blockchain.
type Block struct {
	header       *Header
	uncles       []*Header
	transactions Transactions
	Previoustransactions Transactions
	VoteCast [][]string
	hash atomic.Value
	size atomic.Value

	// Td is used by package core to store the total difficulty
	// of the chain up to and including the block.
	td *big.Int

	// These fields are used by package eth to track
	// inter-peer block relay.
	ReceivedAt   time.Time
	ReceivedFrom interface{}
}

// DeprecatedTd is an old relic for extracting the TD of a block. It is in the
// code solely to facilitate upgrading the database from the old format to the
// new, after which it should be deleted. Do not use!
func (b *Block) DeprecatedTd() *big.Int {
	return b.td
}

// [deprecated by eth/63]
// StorageBlock defines the RLP encoding of a Block stored in the
// state database. The StorageBlock encoding contains fields that
// would otherwise need to be recomputed.
type StorageBlock Block

// "external" block encoding. used for eth protocol, etc.
type extblock struct {
	Header *Header
	Txs    []*Transaction
	PreviousTxs []*Transaction
	Uncles []*Header
	VoteCast [][] string
}

// [deprecated by eth/63]
// "storage" block encoding. used for database.
type storageblock struct {
	Header   *Header
	Txs      []*Transaction
	PreviousTxs []*Transaction
	Uncles   []*Header
	TD       *big.Int
	VoteCast [][] string
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
// NewBlock creates a new block. The input data is copied,
// changes to header and to the field values will not affect the
// block.
//
// The values of TxHash, UncleHash, ReceiptHash and Bloom in header
// are ignored and set to values derived from the given txs, uncles
// and receipts.
func NewBlock(header *Header, txs []*Transaction, uncles []*Header, receipts []*Receipt, previousBlocktxs []*Transaction) *Block {
	b := &Block{header: CopyHeader(header), td: new(big.Int)}
	//This code check the previous trransactions if there is a transaction with the same ID then it is added to the 	//transactions of the current block
	//First it collects the ID of the current transactions 
	var ids [] *big.Int
	for _, n := range txs {
		if (! contains(ids, n.EventID()) && n.EventID()!='0')) {
			ids= append(ids, n.EventID())
		}}
	var neededTx []* Transaction
	// Then it compares the previous block transaction and append if the same id is found 
	for _, n := range previousBlocktxs {
		if (contains(ids, n.EventID()) {
			neededTx = append (neededTx,n)
		}}
	b.Previoustransactions = make(Transactions, len(neededTx))
	copy(b.Previoustransactions, neededTx)
	// TODO: panic if len(txs) != len(receipts)
	if len(txs) == 0 {
		b.header.TxHash = EmptyRootHash
	} else {
		b.header.TxHash = DeriveSha(Transactions(txs))
		b.transactions = make(Transactions, len(txs))
		copy(b.transactions, txs)
	}
	
	var votes [][]*big.Int
	for _, n := range b.transactions {
		log.Info("Vote cast at block is", "data ",fmt.Sprintf("%t",n.ProbTran()))		
		if (n.ProbTran()){
			votes= append(votes,[]*big.Int{n.EventID(),n.Vote()})
	}
	}
	for _, n := range neededTx {		
		if (n.ProbTran()){
			votes= append(votes,[]*big.Int{n.EventID(),n.Vote()})
	}
	}
	var votesPerEvent [] Events
	votesPerEvent = ListEvents(votes)
	for i, _:= range votesPerEvent {
	//fmt.Println ("hello")
		summary := []string{"id",votesPerEvent[i].id.String(), "mean",Mean(votesPerEvent[i].votes).String(), "std",StandardDeviation(votesPerEvent[i].votes).String()}
		b.VoteCast= append(b.VoteCast,summary)
	//lower, upper := NormalConfidenceInterval(ciphertexts)
	//ci = "["+lower.String()+","+upper.String()+"]"
	//VoteCast= [mean, std, ci]
	// caches
		log.Info("Vote cast at block is", "data ",fmt.Sprintf("%x",b.VoteCast))
	}
	if len(receipts) == 0 {
		b.header.ReceiptHash = EmptyRootHash
	} else {
		b.header.ReceiptHash = DeriveSha(Receipts(receipts))
		b.header.Bloom = CreateBloom(receipts)
	}

	if len(uncles) == 0 {
		b.header.UncleHash = EmptyUncleHash
	} else {
		b.header.UncleHash = CalcUncleHash(uncles)
		b.uncles = make([]*Header, len(uncles))
		for i := range uncles {
			b.uncles[i] = CopyHeader(uncles[i])
		}
	}
        //log.Info("Vote cast at block is", "data ",fmt.Sprintf("%d",b.VoteCastCall()))
	return b
}

// NewBlockWithHeader creates a block with the given header data. The
// header data is copied, changes to header and to the field values
// will not affect the block.
func NewBlockWithHeader(header *Header) *Block {
	return &Block{header: CopyHeader(header)}
}

// CopyHeader creates a deep copy of a block header to prevent side effects from
// modifying a header variable.
func CopyHeader(h *Header) *Header {
	cpy := *h
	if cpy.Time = new(big.Int); h.Time != nil {
		cpy.Time.Set(h.Time)
	}
	if cpy.Difficulty = new(big.Int); h.Difficulty != nil {
		cpy.Difficulty.Set(h.Difficulty)
	}
	if cpy.Number = new(big.Int); h.Number != nil {
		cpy.Number.Set(h.Number)
	}
	if cpy.GasLimit = new(big.Int); h.GasLimit != nil {
		cpy.GasLimit.Set(h.GasLimit)
	}
	if cpy.GasUsed = new(big.Int); h.GasUsed != nil {
		cpy.GasUsed.Set(h.GasUsed)
	}
	if len(h.Extra) > 0 {
		cpy.Extra = make([]byte, len(h.Extra))
		copy(cpy.Extra, h.Extra)
	}
	return &cpy
}

// DecodeRLP decodes the Ethereum
func (b *Block) DecodeRLP(s *rlp.Stream) error {
	var eb extblock
	_, size, _ := s.Kind()
	if err := s.Decode(&eb); err != nil {
		return err
	}
	b.header, b.uncles, b.transactions, b.VoteCast, b.Previoustransactions= eb.Header, eb.Uncles, eb.Txs, eb.VoteCast, eb.PreviousTxs 
	b.size.Store(common.StorageSize(rlp.ListSize(size)))
	return nil
}

// EncodeRLP serializes b into the Ethereum RLP block format.
func (b *Block) EncodeRLP(w io.Writer) error {
	log.Info("Vote cast at rlp encoding is", "data ",fmt.Sprintf("%d",b.VoteCastCall()))
	return rlp.Encode(w, extblock{
		Header: b.header,
		Txs:    b.transactions,
		PreviousTxs: b.Previoustransactions,
		Uncles: b.uncles,
		VoteCast: b.VoteCast,
	})
}

// [deprecated by eth/63]
func (b *StorageBlock) DecodeRLP(s *rlp.Stream) error {
	var sb storageblock
	if err := s.Decode(&sb); err != nil {
		return err
	}
	b.header, b.uncles, b.transactions, b.td = sb.Header, sb.Uncles, sb.Txs, sb.TD
	return nil
}

// TODO: copies

func (b *Block) Uncles() []*Header          { return b.uncles }
func (b *Block) Transactions() Transactions { return b.transactions }
func (b *Block) PreviousTransactions() Transactions { return b.Previoustransactions }

func (b *Block) Transaction(hash common.Hash) *Transaction {
	for _, transaction := range b.transactions {
		if transaction.Hash() == hash {
			return transaction
		}
	}
	return nil
}

func (b *Block) Number() *big.Int     { return new(big.Int).Set(b.header.Number) }
func (b *Block) GasLimit() *big.Int   { return new(big.Int).Set(b.header.GasLimit) }
func (b *Block) GasUsed() *big.Int    { return new(big.Int).Set(b.header.GasUsed) }
func (b *Block) Difficulty() *big.Int { return new(big.Int).Set(b.header.Difficulty) }
func (b *Block) Time() *big.Int       { return new(big.Int).Set(b.header.Time) }
func (b *Block) NumberU64() uint64        { return b.header.Number.Uint64() }
func (b *Block) MixDigest() common.Hash   { return b.header.MixDigest }
func (b *Block) Nonce() uint64            { return binary.BigEndian.Uint64(b.header.Nonce[:]) }
func (b *Block) Bloom() Bloom             { return b.header.Bloom }
func (b *Block) Coinbase() common.Address { return b.header.Coinbase }
func (b *Block) Root() common.Hash        { return b.header.Root }
func (b *Block) ParentHash() common.Hash  { return b.header.ParentHash }
func (b *Block) TxHash() common.Hash      { return b.header.TxHash }
func (b *Block) ReceiptHash() common.Hash { return b.header.ReceiptHash }
func (b *Block) UncleHash() common.Hash   { return b.header.UncleHash }
func (b *Block) Extra() []byte            { return common.CopyBytes(b.header.Extra) }

func (b *Block) VoteCastCall() [][]string {
	log.Info("Vote cast at votecastcall is", "data ",fmt.Sprintf("%d",b.VoteCast))
	if votecast:=b.VoteCast; votecast!=nil{
		return votecast
	}
	return nil
}
func (b *Block) Header() *Header { return CopyHeader(b.header) }

// Body returns the non-header content of the block.
func (b *Block) Body() *Body { return &Body{b.transactions, b.uncles, b.VoteCast, b.Previoustransactions} }

func (b *Block) HashNoNonce() common.Hash {
	return b.header.HashNoNonce()
}

func (b *Block) Size() common.StorageSize {
	if size := b.size.Load(); size != nil {
		return size.(common.StorageSize)
	}
	c := writeCounter(0)
	rlp.Encode(&c, b)
	b.size.Store(common.StorageSize(c))
	return common.StorageSize(c)
}

type writeCounter common.StorageSize

func (c *writeCounter) Write(b []byte) (int, error) {
	*c += writeCounter(len(b))
	return len(b), nil
}

func CalcUncleHash(uncles []*Header) common.Hash {
	return rlpHash(uncles)
}

// WithSeal returns a new block with the data from b but the header replaced with
// the sealed one.
func (b *Block) WithSeal(header *Header) *Block {
	cpy := *header

	return &Block{
		header:       &cpy,
		transactions: b.transactions,
		uncles:       b.uncles,
	}
}

// WithBody returns a new block with the given transaction and uncle contents.
func (b *Block) WithBody(transactions []*Transaction, uncles []*Header, voteCast [][] string, previoustransactions []*Transaction) *Block {
	block := &Block{
		header:       CopyHeader(b.header),
		transactions: make([]*Transaction, len(transactions)),
		uncles:       make([]*Header, len(uncles)),
		VoteCast:     voteCast,
		Previoustransactions: make([]*Transaction, len(previoustransactions)), 
	}
	copy(block.transactions, transactions)
	copy(block.Previoustransactions, previoustransactions)
	for i := range uncles {
		block.uncles[i] = CopyHeader(uncles[i])
	}
	return block
}

// Hash returns the keccak256 hash of b's header.
// The hash is computed on the first call and cached thereafter.
func (b *Block) Hash() common.Hash {
	if hash := b.hash.Load(); hash != nil {
		return hash.(common.Hash)
	}
	v := b.header.Hash()
	b.hash.Store(v)
	return v
}

func (b *Block) String() string {
	str := fmt.Sprintf(`Block(#%v): Size: %v {
MinerHash: %x
%v
Transactions:
%v
Uncles:
%v
VoteCast:
}
`, b.Number(), b.Size(), b.header.HashNoNonce(), b.header, b.transactions, b.uncles, b.VoteCast)
	return str
}

func (h *Header) String() string {
	return fmt.Sprintf(`Header(%x):
[
	ParentHash:	    %x
	UncleHash:	    %x
	Coinbase:	    %x
	Root:		    %x
	TxSha		    %x
	ReceiptSha:	    %x
	Bloom:		    %x
	Difficulty:	    %v
	Number:		    %v
	GasLimit:	    %v
	GasUsed:	    %v
	Time:		    %v
	Extra:		    %s
	MixDigest:      %x
	Nonce:		    %x
]`, h.Hash(), h.ParentHash, h.UncleHash, h.Coinbase, h.Root, h.TxHash, h.ReceiptHash, h.Bloom, h.Difficulty, h.Number, h.GasLimit, h.GasUsed, h.Time, h.Extra, h.MixDigest, h.Nonce)
}

type Blocks []*Block

type BlockBy func(b1, b2 *Block) bool

func (self BlockBy) Sort(blocks Blocks) {
	bs := blockSorter{
		blocks: blocks,
		by:     self,
	}
	sort.Sort(bs)
}

type blockSorter struct {
	blocks Blocks
	by     func(b1, b2 *Block) bool
}

func (self blockSorter) Len() int { return len(self.blocks) }
func (self blockSorter) Swap(i, j int) {
	self.blocks[i], self.blocks[j] = self.blocks[j], self.blocks[i]
}
func (self blockSorter) Less(i, j int) bool { return self.by(self.blocks[i], self.blocks[j]) }

func Number(b1, b2 *Block) bool { return b1.header.Number.Cmp(b2.header.Number) < 0 }

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
