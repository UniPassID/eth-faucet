package chain

import (
	"context"
	"crypto/ecdsa"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type TxBuilder interface {
	Sender() common.Address
	Transfer(ctx context.Context, to string, value *big.Int) (common.Hash, error)
	TransferERC20(ctx context.Context, to string, value int64) (common.Hash, error)
}

type TxBuild struct {
	client        bind.ContractTransactor
	privateKey    *ecdsa.PrivateKey
	signer        types.Signer
	fromAddress   common.Address
	tokenAddress  common.Address
	tokenDecimals *big.Int
}

func NewTxBuilder(provider, token string, privateKey *ecdsa.PrivateKey, chainID *big.Int) (TxBuilder, error) {
	client, err := ethclient.Dial(provider)
	if err != nil {
		return nil, err
	}

	if chainID == nil {
		chainID, err = client.ChainID(context.Background())
		if err != nil {
			return nil, err
		}
	}

	tokenAddress := common.HexToAddress(token)

	erc20ABI, err := abi.JSON(strings.NewReader(ERC20ABI))
	if err != nil {
		return nil, err
	}
	callData, err := erc20ABI.Pack("decimals")
	if err != nil {
		return nil, err
	}

	res, err := client.CallContract(context.Background(), ethereum.CallMsg{
		To:   &tokenAddress,
		Data: callData}, nil)
	if err != nil {
		return nil, err
	}

	return &TxBuild{
		client:        client,
		privateKey:    privateKey,
		signer:        types.NewEIP155Signer(chainID),
		fromAddress:   crypto.PubkeyToAddress(privateKey.PublicKey),
		tokenAddress:  tokenAddress,
		tokenDecimals: new(big.Int).SetBytes(res),
	}, nil
}

func (b *TxBuild) Sender() common.Address {
	return b.fromAddress
}

func (b *TxBuild) Transfer(ctx context.Context, to string, value *big.Int) (common.Hash, error) {
	nonce, err := b.client.PendingNonceAt(ctx, b.Sender())
	if err != nil {
		return common.Hash{}, err
	}

	gasLimit := uint64(21000)
	gasPrice, err := b.client.SuggestGasPrice(ctx)
	if err != nil {
		return common.Hash{}, err
	}

	toAddress := common.HexToAddress(to)
	unsignedTx := types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		To:       &toAddress,
		Value:    value,
		Gas:      gasLimit,
		GasPrice: gasPrice,
	})

	signedTx, err := types.SignTx(unsignedTx, b.signer, b.privateKey)
	if err != nil {
		return common.Hash{}, err
	}

	return signedTx.Hash(), b.client.SendTransaction(ctx, signedTx)
}

func (b *TxBuild) TransferERC20(ctx context.Context, to string, value int64) (common.Hash, error) {
	nonce, err := b.client.PendingNonceAt(ctx, b.Sender())
	if err != nil {
		return common.Hash{}, err
	}

	toAddress := common.HexToAddress(to)
	erc20ABI, err := abi.JSON(strings.NewReader(ERC20ABI))
	if err != nil {
		return common.Hash{}, err
	}

	amount := DecimalConvert(value, b.tokenDecimals)
	callData, err := erc20ABI.Pack("transfer", toAddress, amount)
	if err != nil {
		return common.Hash{}, err
	}

	gasPrice, err := b.client.SuggestGasPrice(ctx)
	if err != nil {
		return common.Hash{}, err
	}

	gasLimit, err := b.client.EstimateGas(ctx, ethereum.CallMsg{
		From:     b.fromAddress,
		To:       &b.tokenAddress,
		GasPrice: gasPrice,
		Data:     callData,
	})
	if err != nil {
		return common.Hash{}, err
	}

	unsignedTx := types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		To:       &b.tokenAddress,
		Gas:      gasLimit * 110 / 100,
		GasPrice: gasPrice,
		Data:     callData,
	})

	signedTx, err := types.SignTx(unsignedTx, b.signer, b.privateKey)
	if err != nil {
		return common.Hash{}, err
	}

	return signedTx.Hash(), b.client.SendTransaction(ctx, signedTx)
}
