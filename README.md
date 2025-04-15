# damn-vulnerable-defi

Here I solve Damn Vulnerable DeFi v4 challenges: https://www.damnvulnerabledefi.xyz/ 

1. Unstoppable

Description

There's a tokenized vault with a million DVT tokens deposited. It’s offering flash loans for free, until the grace period ends.
To catch any bugs before going 100% permissionless, the developers decided to run a live beta in testnet. There's a monitoring contract to check liveness of the flashloan feature.
Starting with 10 DVT tokens in balance, show that it's possible to halt the vault. It must stop offering flash loans.

Contracts:
      UnstoppableVault.sol - main logic.
      UnstoppableMonitor.sol - monitoring if vault is functional
      

In UnstoppableVault.sol contract, we have flashLoan function, where the core functionality is implemented. If we break this function, the vault will stop giving loans.

There are 3 checkings before the function starts executing the loan

      if (amount == 0) revert InvalidAmount(0); // fail early
      if (address(asset) != _token) revert UnsupportedCurrency(); // enforce ERC3156 requirement
      uint256 balanceBefore = totalAssets();
      if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance(); // enforce ERC4626 requirement

This is the critical part. If we succeed in making the function always fail one of those checks, the vault will stop giving loans.

Solution

The only checking that is not dependent on function parameters is the third one. 

      if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance(); // enforce ERC4626 requirement

This check creates a strict requirement that the vault's accounting system always match the actual token balance. 

By simply sending DVT tokens to the contract balance, we will successfully break the vault!

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_unstoppable() public checkSolvedByPlayer {
        token.transfer(address(vault), 1);
    }
